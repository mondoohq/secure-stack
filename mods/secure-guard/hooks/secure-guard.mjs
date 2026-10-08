// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// secure-guard — a Claude Code mod for AI secure development.
//
// It puts Mondoo's scanners in the loop as an agent works, routing each tool
// call to the right engine:
//
//  1. Shell guard (xgrep). It holds a Bash tool call, asks xgrep whether the
//     command is risky, and (when it is) shows the findings in a pane with
//     Proceed / Cancel, holding the call until you answer.
//  2. Inline code review (xgrep). After the agent writes or edits code, it scans
//     the file with xgrep (SAST/SCA/secrets) and hands high-confidence findings
//     back as the tool result so the agent can fix them in the same turn.
//  3. IaC policy guard (cnspec). After the agent writes Terraform, a Dockerfile,
//     or a Kubernetes/CloudFormation manifest, it runs cnspec policy checks and
//     hands the violations back the same way.
//
// All inline review is advisory — the edit always lands; only the shell guard
// can hold/block. It prefers a local xgrep; if none new enough is installed it
// fetches one, visibly, from the public npm package. cnspec, if installed, adds
// the IaC checks; if it is not installed, the IaC guard stays silently off.
//
// All scanning is LOCAL: rules execute on this machine (in-process, or via a
// localhost-only daemon). Commands and code are never uploaded and nothing is
// evaluated server-side — the only network activity is the one-time, visible
// binary fetch (the scanner, not your data).
//
// The mod only reaches outside its own code through the injected `$` API
// (`$.process`, `$.http`, `$.fs`, `$.store`, `$.env`, `$.ui`, `$.clock`), so
// `claude plugin validate` can list everything it does before you install it.
//
// ─── Two integration seams that depend on xgrep (marked TODO below) ──────────
//  1. The in-process verdict: `xgrep guard --command <cmd>` scans one command
//     and prints { decision, summary, findings } as JSON. evaluateInProcess
//     calls it. (Needs a recent enough xgrep; older builds lack the flag and
//     the mod fails open.)
//  2. The warm path: reaching a long-running `xgrep guard daemon` over
//     ConnectRPC so each tool call doesn't start a process. The daemon's
//     Evaluate RPC needs to be reachable off the Unix socket (e.g. a
//     token-authenticated localhost transport) — an upstream xgrep change.
//     Until then the mod uses the in-process path.
// ─────────────────────────────────────────────────────────────────────────────

// The agent-neutral engine logic (parsing, filtering, routing, formatting,
// version compare, cnspec bundle mapping) lives in core.mjs, shared with every
// other agent adapter. This file is the Claude Code adapter: the hooks, the
// pane UI, and the xgrep/cnspec I/O driven through the `$` API.
import {
  XGREP_NPM, XGREP_PIN, XGREP_MIN, CNSPEC_INSTALL_URL,
  parseVersion, meetsMin, normalizeVerdict,
  highConfidenceFindings, advisoryText, isScannable,
  iacScanKind, cnspecScanArgs, cnspecBundlesFor, sarifFindings, iacAdvisoryText,
  extractJsonObject,
} from "./core.mjs";

const DOCS_URL = "https://mondoo.com/docs/xgrep/ai-agents/guard-hooks"; // what the guard does
const NPM_URL = "https://www.npmjs.com/package/@mondoohq/xgrep"; // where the binary comes from
const PANE_ID = "secure-guard";
const POLL = "0.25"; // seconds; held in a free `$.process.run(["sleep",…])`
const HOLD_LIMIT_MS = 10 * 60 * 1000;

// cnspec (IaC policy engine) resolution state. cnspec has no npm package, so
// resolution is CNSPEC_PATH → `cnspec` on PATH → unavailable (IaC guard off).
const IAC_TIMEOUT_MS = 30000; // a policy scan is heavier than a per-file grep
let cnspecBackend = null; // { mode: "ok", cmd } | { mode: "unavailable", reason }

// Inline review timeout; fail-open on any error/timeout. The skip set + the
// "is this file worth scanning" decision live in core (isScannable).
const REVIEW_TIMEOUT_MS = 10000;

// Resolved once per session: how we reach xgrep this session.
//   { mode: "daemon", cmd, addr, token } | { mode: "inproc", cmd } |
//   { mode: "unavailable", reason }
let backend = null;
// The call currently held for review, or null. One at a time.
let held = null;

export function register(on) {
  on("session.start", async ($, e, next) => {
    // Resolve the engines in the background so the session starts right away.
    $.clock.after(0, () => ensureBackend($).catch(() => {}));
    $.clock.after(0, () => ensureCnspec($).catch(() => {}));
    try {
      await $.command.register({
        name: "secure-guard",
        description: "Show how secure-guard is reaching xgrep and cnspec",
      });
    } catch {
      // name already taken — fine
    }
    return next(e);
  });

  // A /secure-guard command the user can run to see (and re-resolve) the engines.
  on("command.run", { command: "secure-guard" }, async ($) => {
    const b = await ensureBackend($);
    const xline = {
      daemon: `warm daemon at ${b.addr}`,
      inproc: `in-process via ${b.cmd?.join(" ")}`,
      unavailable: `not available: ${b.reason}`,
    }[b.mode];
    const c = await ensureCnspec($);
    const cline = c.mode === "ok" ? `via ${c.cmd.join(" ")}` : `not available: ${c.reason}`;
    return {
      text:
        `secure-guard\n` +
        `  xgrep (shell + code): ${xline}\n` +
        `  cnspec (IaC policy):  ${cline}\n` +
        `Docs: ${DOCS_URL}\n` +
        `npm package (xgrep): ${NPM_URL}`,
    };
  });

  // The guard itself: scan a Bash command before it runs. The whole body is
  // wrapped so any unexpected throw fails OPEN (the command runs) rather than
  // breaking the gate — a scanner mod must never wedge the user's session.
  on("tool.call", { tool: "Bash" }, async ($, e, next) => {
    try {
      return await guardBashCall($, e, next);
    } catch (err) {
      $.ui.log(`xgrep guard: unexpected error (${err?.message ?? err}); allowing`);
      return next(e);
    }
  });

  // Inline review: let the write/edit happen, then scan the file it touched and,
  // if there are high-confidence security findings, return them as the tool
  // result so Claude sees them and can fix them in the same turn. `next` runs the
  // tool exactly once (outside the scan try/catch), so any scan error fails OPEN
  // — the edit stays, we just stay quiet.
  on("tool.call", { tool: ["Write", "Edit", "MultiEdit"] }, async ($, e, next) => {
    const r = await next(e);
    if (!r || r.deny || r.isError) return r; // tool blocked or failed — nothing landed
    try {
      // Route by artifact: IaC (Terraform/Dockerfile/K8s/CFN) → cnspec policy;
      // everything else scannable → xgrep code review.
      const kind = iacScanKind(String(e.file_path ?? ""), typeof e.content === "string" ? e.content : undefined);
      if (kind) return await reviewIac($, e, r, kind);
      return await reviewEdit($, e, r);
    } catch (err) {
      $.ui.log(`secure-guard: inline review error (${err?.message ?? err}); not reporting`);
      return r;
    }
  });

  on("ui.render", { component: "Pane" }, ($, e, next) => {
    if (e.requestId !== PANE_ID || held === null) return next(e);
    return draw($.ui.resolve(e), held);
  });
  on("ui.render", { component: "AbovePrompt" }, ($, e, next) => {
    if (held === null || held.where !== "band") return next(e);
    return draw($.ui.resolve(e), held);
  });
}

// guardBashCall holds + reviews a single Bash command. Separated out so the
// registered hook stays a thin try/catch wrapper around it (fail-open).
async function guardBashCall($, e, next) {
  {
    const command = String(e.command ?? "");
    if (command.trim() === "") return next(e);

    const b = await ensureBackend($);
    if (b.mode === "unavailable") {
      // Fail OPEN: never block the user's work because the scanner couldn't load.
      // (A fail-closed policy could be a userConfig option.)
      $.ui.log(`xgrep guard: ${b.reason} — not scanning. ${DOCS_URL}`);
      return next(e);
    }

    let verdict;
    try {
      verdict = await evaluate($, b, command);
    } catch (err) {
      $.ui.log(`xgrep guard: evaluate failed (${err?.message ?? err}); allowing`);
      return next(e); // fail open on an evaluate error
    }
    if (!verdict || verdict.decision === "allow") {
      return next(e);
    }

    // Risky → hold the call behind a pane until the user decides.
    while (held !== null) {
      if (next.signal.aborted) return denyResult("the turn was interrupted", verdict);
      await $.process.run(["sleep", POLL], { timeoutMs: 5000 });
    }
    const mine = { command, verdict, decision: null, where: "pane" };
    held = mine;
    let opened = { isPlaced: false };
    try {
      opened = await $.ui.open({ id: PANE_ID, title: "xgrep guard", focus: true, rows: paneRows(verdict) });
      if (!opened.isPlaced) mine.where = "band";
      $.ui.invalidate("ui.render");

      const start = await $.clock.now();
      while (mine.decision === null) {
        if (next.signal.aborted) { mine.decision = "interrupted"; break; }
        if ((await $.clock.now()) - start > HOLD_LIMIT_MS) { mine.decision = "timeout"; break; }
        await $.process.run(["sleep", POLL], { timeoutMs: 5000 });
      }
    } catch {
      mine.decision = "error";
    } finally {
      try { if (opened.isPlaced) await $.ui.close({ id: PANE_ID }); } catch {}
      if (held === mine) held = null;
      $.ui.invalidate("ui.render");
    }

    if (mine.decision === "proceed") {
      $.ui.toast("xgrep guard: running it");
      return next(e);
    }
    const why = {
      cancel: "you pressed Cancel",
      timeout: "no answer within 10 minutes",
      interrupted: "the turn was interrupted",
      error: "xgrep guard hit an error while holding it",
    }[mine.decision] ?? "no answer was recorded";
    return denyResult(why, verdict);
  }
}

function denyResult(why, verdict) {
  return {
    deny:
      `xgrep guard held this command and did not run it: ${why}. ` +
      `xgrep flagged: ${verdict.summary}. Do not retry it unless the user asks you to.`,
  };
}

// ─── Backend resolution ──────────────────────────────────────────────────────

// ensureBackend resolves (once per session) how to reach an xgrep new enough
// for the guard. Precedence:
//   1. XGREP_PATH env, if it meets XGREP_MIN
//   2. `xgrep` on PATH, if it meets XGREP_MIN
//   3. the pinned release via `npx` — fetched VISIBLY — when nothing local
//      qualifies: a fresh install, OR an installed xgrep too old for the guard,
//      which the mod "updates" past the way an IDE pulls its own managed tool
//   4. unavailable
async function ensureBackend($) {
  if (backend) return backend;

  const candidates = [];
  const envPath = $.env.get("XGREP_PATH");
  if (envPath) candidates.push([envPath]);
  candidates.push(["xgrep"]);

  let outdated = null; // a local xgrep that runs but is older than XGREP_MIN
  for (const cmd of candidates) {
    const p = await probe($, cmd);
    if (!p.ok) continue;
    if (meetsMin(p.version)) {
      backend = await connectOrInproc($, cmd);
      return backend;
    }
    outdated = p.version ?? "an older build";
  }

  // Nothing local qualifies. Fetch the pinned release via npx — this installs
  // xgrep when it is missing and updates past a too-old install, the way
  // VS Code / IntelliJ pull their own managed copy rather than touch yours.
  if (outdated) {
    $.ui.toast(`xgrep guard: xgrep ${outdated} is older than ${XGREP_MIN}; updating to ${XGREP_PIN}`);
    $.ui.log(`xgrep guard: your xgrep (${outdated}) predates the guard's minimum (${XGREP_MIN}), so the shell check can't run on it. Fetching ${XGREP_NPM}@${XGREP_PIN} via npx for this session. To update your own install: npm i -g ${XGREP_NPM}@latest. See ${DOCS_URL}`);
  } else {
    $.ui.toast(`xgrep guard: fetching xgrep from npm (${XGREP_NPM})`);
    $.ui.log(`xgrep guard: xgrep is not installed. Fetching ${XGREP_NPM}@${XGREP_PIN} via npx. See ${DOCS_URL}`);
  }
  const npx = ["npx", "-y", `${XGREP_NPM}@${XGREP_PIN}`];
  const p = await probe($, npx);
  if (p.ok && meetsMin(p.version)) {
    backend = await connectOrInproc($, npx);
    return backend;
  }
  backend = { mode: "unavailable", reason: `no xgrep >= ${XGREP_MIN} found or fetchable (${XGREP_NPM}). Install it: ${NPM_URL}` };
  return backend;
}

// probe runs `xgrep version` and returns whether it ran and the semver it
// reported (e.g. "xgrep 0.80.0 (commit: …)" -> "0.80.0").
async function probe($, cmd) {
  try {
    const r = await $.process.run([...cmd, "version"], { timeoutMs: 120000 });
    if (r.exitCode !== 0) return { ok: false };
    return { ok: true, version: parseVersion(r.stdout) };
  } catch {
    return { ok: false };
  }
}

// connectOrInproc: start/reach the warm daemon over ConnectRPC if possible, else
// use the in-process path. The daemon path needs an upstream xgrep change (the
// Evaluate RPC reachable off the Unix socket), so today this returns in-process.
async function connectOrInproc($, cmd) {
  // TODO: start `xgrep guard daemon --addr 127.0.0.1:0
  // --token-file <tmp>` (or reuse a running one), read its addr + token, confirm
  // GuardService is reachable, and return { mode: "daemon", cmd, addr, token }.
  // Cache addr/token in $.store so later sessions reuse the warm daemon.
  return { mode: "inproc", cmd };
}

// ─── Evaluate ────────────────────────────────────────────────────────────────

// evaluate returns a verdict: { decision: "allow"|"ask"|"deny", summary, lines }.
async function evaluate($, b, command) {
  if (b.mode === "daemon") return evaluateConnect($, b, command);
  return evaluateInProcess($, b, command);
}

// evaluateConnect calls GuardService.Evaluate over the Connect protocol: a plain
// HTTP POST to /<service>/<method> with a JSON body. (Needs the upstream change
// that makes Evaluate reachable off the Unix socket.)
async function evaluateConnect($, b, command) {
  const url = `http://${b.addr}/xgrep.guard.v1.GuardService/Evaluate`;
  const res = await $.http.fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      // TODO: match the daemon's token scheme for the --token-file TCP path.
      Authorization: `Bearer ${b.token}`,
    },
    // TODO: match the real Evaluate request message shape.
    body: JSON.stringify({ command }),
  });
  if (!res.ok) throw new Error(`daemon Evaluate HTTP ${res.status}`);
  return normalizeVerdict(JSON.parse(res.text));
}

// evaluateInProcess shells out to xgrep for a one-shot verdict.
async function evaluateInProcess($, b, command) {
  // `xgrep guard --command <cmd>` scans one command and prints
  // { decision, summary, findings:[…] } as JSON, exiting 0.
  const r = await $.process.run([...b.cmd, "guard", "--command", command], { timeoutMs: 15000 });
  if (r.stdout && r.stdout.trim().startsWith("{")) {
    try { return normalizeVerdict(JSON.parse(r.stdout)); } catch {}
  }
  // No parseable verdict (e.g. an xgrep too old to know --command) → fail open.
  return { decision: "allow", summary: "", lines: [] };
}

// ─── Inline review ───────────────────────────────────────────────────────────

// reviewEdit scans the file a Write/Edit/MultiEdit just touched and, if there are
// high-confidence security findings, returns the tool result augmented with them.
// `r` is what the tool itself returned (the write already happened). On anything
// uninteresting it returns `r` unchanged.
async function reviewEdit($, e, r) {
  if (!r || r.deny || r.isError) return r; // tool blocked or failed — nothing landed
  const file = String(e.file_path ?? "");
  if (!file || !isScannable(file)) return r;

  const b = await ensureBackend($);
  if (b.mode === "unavailable") return r; // scanner not here — stay quiet (fail open)

  const findings = await scanFile($, b, file);
  if (findings.length === 0) return r;
  return { result: advisoryText(file, findings) };
}

// scanFile runs xgrep over one file and returns the high-confidence security
// findings. Filtering is done here on the JSON (confidence HIGH, not a test/
// fixture path) rather than via the CLI severity floor — a rule's `confidence`
// is the reliable "this is real" signal; `severity` can read INFO on a
// high-confidence match.
async function scanFile($, b, file) {
  const run = await $.process.run([...b.cmd, "scan", file, "--json"], { timeoutMs: REVIEW_TIMEOUT_MS });
  const out = (run.stdout ?? "").trim();
  if (!out.startsWith("{")) return []; // no JSON (e.g. an xgrep too old) → stay quiet
  let doc;
  try { doc = JSON.parse(out); } catch { return []; }
  return highConfidenceFindings(doc);
}

// ─── cnspec (IaC policy) engine ──────────────────────────────────────────────

// ensureCnspec resolves cnspec once per session: CNSPEC_PATH → `cnspec` on PATH
// → unavailable. cnspec has no npm package, so when it is absent the IaC guard
// simply stays off (fail-open); we point the user at the install docs.
async function ensureCnspec($) {
  if (cnspecBackend) return cnspecBackend;
  const candidates = [];
  const envPath = $.env.get("CNSPEC_PATH");
  if (envPath) candidates.push([envPath]);
  candidates.push(["cnspec"]);
  for (const cmd of candidates) {
    try {
      const r = await $.process.run([...cmd, "version"], { timeoutMs: 120000 });
      if (r.exitCode === 0) { cnspecBackend = { mode: "ok", cmd }; return cnspecBackend; }
    } catch { /* try next */ }
  }
  cnspecBackend = { mode: "unavailable", reason: `cnspec not installed — install it for IaC policy checks: ${CNSPEC_INSTALL_URL}` };
  return cnspecBackend;
}

// reviewIac scans an IaC file the agent just wrote with cnspec and, if policy
// checks fail, returns them as the tool result. Fail-open: cnspec missing or any
// error returns the original result unchanged.
async function reviewIac($, e, r, kind) {
  const file = String(e.file_path ?? "");
  if (!file) return r;
  const b = await ensureCnspec($);
  if (b.mode !== "ok") return r; // cnspec not installed — stay quiet
  const findings = await cnspecScan($, b, kind, file);
  if (findings.length === 0) return r;
  return { result: iacAdvisoryText(file, kind, findings) };
}

async function cnspecScan($, b, kind, file) {
  const bundles = cnspecBundlesFor(kind, $.env.get("CNSPEC_POLICY_BUNDLE") || "", $.env.get("CNSPEC_CONTENT_DIR") || "");
  const run = await $.process.run([...b.cmd, ...cnspecScanArgs(kind, file, bundles)], { timeoutMs: IAC_TIMEOUT_MS });
  const obj = extractJsonObject(run.stdout ?? "");
  if (!obj) return [];
  let doc;
  try { doc = JSON.parse(obj); } catch { return []; }
  return sarifFindings(doc);
}

// ─── Drawing (pane / band) ───────────────────────────────────────────────────

function paneRows(v) {
  return Math.min(24, 8 + (v.lines?.length ?? 0));
}

function draw(t, state) {
  const { Box, Text, Button } = t;
  const { verdict } = state;
  const list = (verdict.lines ?? []).map((line, i) =>
    Text({ key: `l${i}`, children: `  ${line}`, wrap: "truncate-end" })
  );
  const decide = (choice) => () => { if (state.decision === null) state.decision = choice; };
  return Box({
    flexDirection: "column",
    borderStyle: "round",
    borderColor: "yellow",
    paddingX: 1,
    children: [
      Text({ key: "title", bold: true, color: "yellow", children: "⚠ xgrep guard" }),
      Text({ key: "cmd", children: [Text({ dimColor: true, children: "Command  " }), Text({ bold: true, children: state.command })], wrap: "truncate-end" }),
      verdict.summary ? Text({ key: "sum", children: [Text({ dimColor: true, children: "xgrep    " }), Text({ color: "red", bold: true, children: verdict.summary })] }) : null,
      list.length ? Box({ key: "list", flexDirection: "column", marginTop: 1, children: list }) : null,
      Box({
        key: "buttons",
        marginTop: 1,
        gap: 2,
        children: [
          Button({ key: "proceed", label: "Proceed", hotkey: "1", plain: true, onPress: decide("proceed") }),
          Button({ key: "cancel", label: "Cancel", hotkey: "2", plain: true, autoFocus: true, onPress: decide("cancel") }),
          Text({ key: "hint", dimColor: true, children: "Claude is waiting on your answer" }),
        ],
      }),
    ],
  });
}
