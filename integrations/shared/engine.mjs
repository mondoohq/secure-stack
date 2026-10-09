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
//         → OR `cnspec scan` the proposed IaC        (Terraform/Dockerfile/K8s/CFN),
//            plus `xgrep scan` for Terraform/Dockerfiles (hard-coded secrets)
//
// A finding → { decision: "deny", reason }, else { decision: "allow" }; a shell
// verdict xgrep marks "ask" stays "ask", for agents that can prompt (Codex) —
// the rest treat it as deny. The scanners run through an injectable
// `run` (which, args) => { available, stdout } so routing is unit-testable
// without any binary. Everything fails open: a missing/old/erroring scanner
// yields "allow" — a guard must never wedge a session.

import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, readFileSync, mkdirSync, existsSync, readdirSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join, dirname } from "node:path";
import {
  normalizeVerdict, highConfidenceFindings, advisoryText, isScannable,
  iacScanKind, alsoCodeScan, combineAdvisories,
  cnspecScanArgs, cnspecPolicySource, sarifFindings, iacAdvisoryText,
  parseJsonObject, IAC_TIMEOUT_MS, XGREP_NPM, XGREP_PIN, npxNodeModulesDir, nativeXgrepCandidates,
} from "../../mods/secure-guard/hooks/core.mjs";

export const SCAN_TIMEOUT_MS = 20000;
export { IAC_TIMEOUT_MS }; // shared with the Claude mod, defined in core

const allow = () => ({ decision: "allow" });
const deny = (reason) => ({ decision: "deny", reason });
const ask = (reason) => ({ decision: "ask", reason });

// The pinned xgrep the adapters fetch when none is installed — the same release
// the Claude mod pins (core.mjs), so every agent runs the same scanner.
export const XGREP_NPX = ["npx", "-y", `${XGREP_NPM}@${XGREP_PIN}`];
// Codex and Vibe start a new hook process for every tool call, so the npx
// fallback's answer is remembered here rather than re-probed through npx each
// time: a success for good, a failure (offline, say) for NPX_RETRY_MS so a
// hook doesn't retry npx on every call. Keyed by the pin: a new pin probes
// afresh. A capable local xgrep is always checked first, so this never hides
// one installed later. It lives in the user's own cache dir — not the shared
// temp dir, where another user could plant the path first.
export const XGREP_NPX_CACHE = join(
  process.env.XDG_CACHE_HOME || join(homedir(), ".cache"), "secure-guard", `xgrep-npx-${XGREP_PIN}.json`);
export const NPX_RETRY_MS = 10 * 60 * 1000;

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
//
// xgrep resolution matches the Claude mod: XGREP_PATH → `xgrep` on PATH → the
// pinned release via npx, fetched visibly (a line on stderr naming the package)
// when no capable local xgrep exists. `deps` makes the I/O injectable for tests.
export function makeRealRunner(env = process.env, deps = {}) {
  const spawn = deps.spawnSync ?? spawnSync;
  const cacheFile = deps.cacheFile ?? XGREP_NPX_CACHE;
  const notify = deps.notify ?? ((line) => process.stderr.write(line + "\n"));
  const clock = deps.clock ?? Date;
  const exists = deps.existsSync ?? existsSync;
  const list = deps.readdir ?? ((dir) => { try { return readdirSync(dir); } catch { return []; } });
  let xgrep;  // undefined = unresolved, null = unavailable, [argv…] = resolved
  let cnspec;
  const hasCommandFlag = (cmd) => {
    try {
      const r = spawn(cmd[0], [...cmd.slice(1), "guard", "--command", "echo ok"], { encoding: "utf8", timeout: 120000 });
      return (r.stdout ?? "").trim().startsWith("{");
    } catch {
      return false;
    }
  };
  const resolveXgrep = () => {
    if (xgrep !== undefined) return xgrep;
    xgrep = null;
    for (const cmd of [env.XGREP_PATH && [env.XGREP_PATH], ["xgrep"]].filter(Boolean)) {
      if (hasCommandFlag(cmd)) { xgrep = cmd; return xgrep; }
    }
    // Nothing local is new enough: the pinned release via npx. Remembered
    // across hook processes; announced the first time it is fetched. Once
    // fetched, the native binary inside the npx package is called directly —
    // npx re-resolves the package on every call, seconds on a busy machine.
    const cached = readNpxCache(cacheFile);
    if (cached?.ok) {
      xgrep = cached.bin && exists(cached.bin) ? [cached.bin] : XGREP_NPX;
      return xgrep;
    }
    if (cached?.failedAt && clock.now() - cached.failedAt < NPX_RETRY_MS) return xgrep; // backing off
    notify(`secure-guard: no xgrep with 'guard --command' installed; fetching ${XGREP_NPM}@${XGREP_PIN} ` +
      `from npm via npx (the scanner, not your data). Install it to skip this: npm i -g ${XGREP_NPM}`);
    const ok = hasCommandFlag(XGREP_NPX);
    let bin = null;
    if (ok) {
      bin = resolveNativeXgrep();
      xgrep = bin ? [bin] : XGREP_NPX;
    }
    writeNpxCache(cacheFile, ok ? { ok: true, ...(bin ? { bin } : {}) } : { failedAt: clock.now() });
    return xgrep;
  };
  // resolveNativeXgrep finds the platform binary inside the pinned npx package
  // (see core.mjs); null when it can't be found or lacks `guard --command`.
  const resolveNativeXgrep = () => {
    for (const finder of [["which", "xgrep"], ["where", "xgrep"]]) {
      let r;
      try {
        r = spawn("npx", ["-y", "-p", `${XGREP_NPM}@${XGREP_PIN}`, ...finder], { encoding: "utf8", timeout: 120000 });
      } catch {
        continue;
      }
      if (r?.status !== 0) continue;
      const shim = String(r.stdout ?? "").split(/\r?\n/).map((l) => l.trim()).find(Boolean);
      const nodeModules = npxNodeModulesDir(shim);
      if (!nodeModules) continue;
      const scope = join(nodeModules, "@mondoohq");
      for (const rel of nativeXgrepCandidates(list(scope))) {
        const bin = join(scope, rel);
        if (exists(bin) && hasCommandFlag([bin])) return bin;
      }
    }
    return null;
  };
  const resolveCnspec = () => {
    if (cnspec !== undefined) return cnspec;
    cnspec = null;
    for (const cmd of [env.CNSPEC_PATH && [env.CNSPEC_PATH], ["cnspec"]].filter(Boolean)) {
      try {
        const r = spawn(cmd[0], [...cmd.slice(1), "version"], { encoding: "utf8", timeout: 120000 });
        if (r.status === 0) { cnspec = cmd; break; }
      } catch { /* next */ }
    }
    return cnspec;
  };
  return (which, args, timeout) => {
    const cmd = which === "xgrep" ? resolveXgrep() : resolveCnspec();
    if (!cmd) return { available: false, stdout: "" };
    const r = spawn(cmd[0], [...cmd.slice(1), ...args], { encoding: "utf8", timeout, maxBuffer: 64 << 20 });
    return { available: true, stdout: r.stdout ?? "", status: r.status };
  };
}

// The npx cache is best effort both ways: unreadable or malformed means "not
// cached", and a failed write just means the next process probes again.
function readNpxCache(file) {
  try {
    const v = JSON.parse(readFileSync(file, "utf8"));
    return v && typeof v === "object" ? v : null;
  } catch {
    return null;
  }
}

function writeNpxCache(file, value) {
  try {
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    writeFileSync(file, JSON.stringify(value), { mode: 0o600 });
  } catch { /* best effort */ }
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
    const source = cnspecPolicySource(kind, env);
    const args = cnspecScanArgs(kind, f, source.bundles, { platform: source.kind === "platform" });
    const r = run("cnspec", args, IAC_TIMEOUT_MS);
    const doc = r.available ? parseJsonObject(r.stdout) : null;
    return doc ? sarifFindings(doc) : [];
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// These adapters run BEFORE the tool: a blocked write never landed.
const PRE_WRITE = Object.freeze({ written: false });

// shellReason phrases a blocked shell command. xgrep's summary already says how
// to fix it (e.g. "remove the secret and retry"), so the reason adds only that
// the command did not run — not a blanket "do not retry" that contradicts it.
export function shellReason(summary) {
  const s = String(summary || "xgrep flagged this command as risky").trim().replace(/\.+$/, "");
  return `secure-guard blocked this command before it ran. ${s}.`;
}

function safely(scan) {
  try { return scan(); } catch { return []; }
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
      if (v.decision === "allow") return allow();
      const reason = shellReason(v.summary);
      return v.decision === "ask" ? ask(reason) : deny(reason);
    }

    if (ev.tool === "Write" && ev.filePath && typeof ev.content === "string") {
      const kind = iacScanKind(ev.filePath, ev.content);
      if (kind) {
        // Each engine fails open on its own: one erroring never hides the other.
        const iac = safely(() => scanIac(run, env, kind, ev.filePath, ev.content));
        const code = alsoCodeScan(kind) && isScannable(ev.filePath)
          ? safely(() => scanCode(run, ev.filePath, ev.content))
          : [];
        const text = combineAdvisories([
          iac.length ? iacAdvisoryText(ev.filePath, kind, iac, PRE_WRITE) : null,
          code.length ? advisoryText(ev.filePath, code, PRE_WRITE) : null,
        ]);
        return text ? deny(text) : allow();
      }
      const f = scanCode(run, ev.filePath, ev.content);
      return f.length ? deny(advisoryText(ev.filePath, f, PRE_WRITE)) : allow();
    }

    return allow();
  } catch {
    return allow(); // fail open on any unexpected error
  }
}
