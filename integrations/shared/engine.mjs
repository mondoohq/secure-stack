// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// secure-guard engine — the one place that turns a tool event into a
// guard decision by driving the scanners. Every adapter (the Codex/Vibe stdin
// hook, the Pi extension, the opencode plugin) builds a neutral event and calls
// evaluate(); only the agent's I/O and decision-surfacing differ.
//
// Routing (same as the Claude mod):
//   Bash  → `xgrep guard --command <cmd>`           (secrets/PII + dangerous command)
//   Write → `xgrep scan` the proposed code          (OWASP Top 10 / SAST / secrets)
//         → OR `cnspec scan` the proposed IaC        (Terraform/Dockerfile/K8s/CFN)
//
// A finding → { decision: "deny", reason }, else { decision: "allow" }. The
// scanners run through an injectable `run` (which, args) => { available, stdout }
// so routing is unit-testable without any binary. Everything fails open: a
// missing/old/erroring scanner yields "allow" — a guard must never wedge a session.

import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  normalizeVerdict, highConfidenceFindings, advisoryText,
  iacScanKind, cnspecScanArgs, cnspecBundlesFor, sarifFindings, iacAdvisoryText,
  extractJsonObject,
} from "../../mods/secure-guard/hooks/core.mjs";

export const SCAN_TIMEOUT_MS = 20000;
// cnspec loads several bundles and compiles MQL; a real IaC scan is ~20–30s, so
// the budget is generous — a timeout fails open, which must not hit a slow scan.
export const IAC_TIMEOUT_MS = 90000;

const allow = () => ({ decision: "allow" });
const deny = (reason) => ({ decision: "deny", reason });

// toEvent normalizes an agent's (toolName, toolInput) into the neutral event the
// engine routes on. Tolerant of the field-name variants agents use for the path
// (file_path / filePath / path) and command/content.
export function toEvent(toolName, input) {
  const i = input || {};
  return {
    tool: toolName ?? "",
    command: i.command ?? "",
    filePath: i.file_path ?? i.filePath ?? i.path ?? "",
    content: typeof i.content === "string" ? i.content : undefined,
  };
}

// makeRealRunner resolves xgrep/cnspec once (confirming xgrep supports
// `guard --command` rather than trusting a version), caches them, and spawns.
// Returns { available:false } when a scanner is absent → the caller fails open.
export function makeRealRunner(env = process.env) {
  let xgrep;  // undefined = unresolved, null = unavailable, [argv…] = resolved
  let cnspec;
  const resolveXgrep = () => {
    if (xgrep !== undefined) return xgrep;
    xgrep = null;
    for (const cmd of [env.XGREP_PATH && [env.XGREP_PATH], ["xgrep"]].filter(Boolean)) {
      try {
        const r = spawnSync(cmd[0], [...cmd.slice(1), "guard", "--command", "echo ok"], { encoding: "utf8", timeout: 120000 });
        if ((r.stdout ?? "").trim().startsWith("{")) { xgrep = cmd; break; }
      } catch { /* next */ }
    }
    return xgrep;
  };
  const resolveCnspec = () => {
    if (cnspec !== undefined) return cnspec;
    cnspec = null;
    for (const cmd of [env.CNSPEC_PATH && [env.CNSPEC_PATH], ["cnspec"]].filter(Boolean)) {
      try {
        const r = spawnSync(cmd[0], [...cmd.slice(1), "version"], { encoding: "utf8", timeout: 120000 });
        if (r.status === 0) { cnspec = cmd; break; }
      } catch { /* next */ }
    }
    return cnspec;
  };
  return (which, args, timeout) => {
    const cmd = which === "xgrep" ? resolveXgrep() : resolveCnspec();
    if (!cmd) return { available: false, stdout: "" };
    const r = spawnSync(cmd[0], [...cmd.slice(1), ...args], { encoding: "utf8", timeout, maxBuffer: 64 << 20 });
    return { available: true, stdout: r.stdout ?? "", status: r.status };
  };
}

function scanCode(run, filePath, content) {
  const dir = mkdtempSync(join(tmpdir(), "sdg-"));
  try {
    const f = join(dir, filePath.split(/[\\/]/).pop() || "file");
    writeFileSync(f, content);
    const r = run("xgrep", ["scan", f, "--json"], SCAN_TIMEOUT_MS);
    const t = (r.stdout || "").trim();
    return r.available && t.startsWith("{") ? highConfidenceFindings(JSON.parse(t)) : [];
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

function scanIac(run, env, kind, filePath, content) {
  const dir = mkdtempSync(join(tmpdir(), "sdg-"));
  try {
    const name = kind === "docker" ? "Dockerfile" : (filePath.split(/[\\/]/).pop() || "main.tf");
    const f = join(dir, name);
    writeFileSync(f, content);
    const bundles = cnspecBundlesFor(kind, env.CNSPEC_POLICY_BUNDLE || "", env.CNSPEC_CONTENT_DIR || "");
    const r = run("cnspec", cnspecScanArgs(kind, f, bundles), IAC_TIMEOUT_MS);
    const obj = r.available ? extractJsonObject(r.stdout) : null;
    return obj ? sarifFindings(JSON.parse(obj)) : [];
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// evaluate: neutral event → { decision: "allow" | "deny", reason? }.
// ev = { tool, command, filePath, content }. opts: { run, env }.
export function evaluate(ev, opts = {}) {
  try {
    const env = opts.env || process.env;
    const run = opts.run || makeRealRunner(env);

    if (ev.tool === "Bash" || ev.tool === "shell") {
      if (!ev.command || !ev.command.trim()) return allow();
      const r = run("xgrep", ["guard", "--command", ev.command], SCAN_TIMEOUT_MS);
      if (!r.available) return allow();
      const t = (r.stdout || "").trim();
      const v = t.startsWith("{") ? normalizeVerdict(JSON.parse(t)) : { decision: "allow" };
      return v.decision === "allow"
        ? allow()
        : deny(`secure-guard: ${v.summary || "risky command"}. Do not retry unless the user asks.`);
    }

    if (ev.tool === "Write" && ev.filePath && typeof ev.content === "string") {
      const kind = iacScanKind(ev.filePath, ev.content);
      if (kind) {
        const f = scanIac(run, env, kind, ev.filePath, ev.content);
        return f.length ? deny(iacAdvisoryText(ev.filePath, kind, f)) : allow();
      }
      const f = scanCode(run, ev.filePath, ev.content);
      return f.length ? deny(advisoryText(ev.filePath, f)) : allow();
    }

    return allow();
  } catch {
    return allow(); // fail open on any unexpected error
  }
}
