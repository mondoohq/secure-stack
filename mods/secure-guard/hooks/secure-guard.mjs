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
//     back beside the tool result so the agent can fix them in the same turn.
//  3. IaC policy guard (cnspec). After the agent writes or edits Terraform, a
//     Dockerfile, or a Kubernetes/CloudFormation manifest, it runs cnspec policy
//     checks and hands the violations back the same way. Terraform and
//     Dockerfiles get the xgrep code review too, for hard-coded secrets.
//
// All inline review is advisory — the edit always lands; only the shell guard
// can hold/block. It prefers a local xgrep; if none new enough is installed it
// fetches one, visibly, from the public npm package. cnspec, if installed, adds
// the IaC checks; if it is not installed, the IaC guard stays silently off.
//
// All scanning is LOCAL: rules execute on this machine (in-process, or via a
// localhost-only daemon). Commands and code are never uploaded and nothing is
// evaluated server-side. What does come DOWN, each time visibly: the xgrep
// binary when none new enough is installed, and — unless CNSPEC_CONTENT_DIR
// points at a local copy — the latest public cnspec policy bundles. Those are
// policies, not your data; cnspec runs --incognito and reports nothing. The one
// exception is opt-in: CNSPEC_USE_PLATFORM runs the policies assigned in your
// Mondoo Platform space, and cnspec reports those scan results to that space.
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
  iacScanKind, iacNeedsContent, alsoCodeScan, combineAdvisories,
  cnspecScanArgs, cnspecPolicySource, cnspecPolicyNotice, sarifFindings, iacAdvisoryText,
  parseJsonObject, IAC_TIMEOUT_MS,
  FP_REPO, FP_LABEL, validateFpReport, fpReproArgs, fpReproduces, fpIssue, fpIssueUrl,
  findingsNotice, findingsToast,
} from "./core.mjs";

// The tool the agent calls to report an xgrep false positive (listed to the
// model as mcp__secure-guard__report_false_positive).
// (The tool.call matcher spells the full name out so `claude plugin validate`
// can list it.)
const FP_TOOL = "report_false_positive";
// Appended to xgrep code advisories so the agent knows the way out of a wrong
// finding exists — and that the user stays in control of it.
const FP_HINT =
  `If you are confident a finding is a false positive, explain why instead of changing correct ` +
  `code, and you may offer to report it with the ${FP_TOOL} tool (the user reviews the issue ` +
  `before anything is filed).`;

const DOCS_URL = "https://mondoo.com/docs/xgrep/ai-agents/guard-hooks"; // what the guard does
const NPM_URL = "https://www.npmjs.com/package/@mondoohq/xgrep"; // where the binary comes from
const PANE_ID = "secure-guard";
const POLL = "0.25"; // seconds; held in a free `$.process.run(["sleep",…])`
const HOLD_LIMIT_MS = 10 * 60 * 1000;

// cnspec (IaC policy engine) resolution state. cnspec has no npm package, so
// resolution is CNSPEC_PATH → `cnspec` on PATH → unavailable (IaC guard off).
let cnspecBackend = null; // { mode: "ok", cmd } | { mode: "unavailable", reason }
// Whether this session has shown the policy-source notice (download/Platform).
let cnspecNoticeShown = false;

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
    try {
      await $.tool.register({
        name: FP_TOOL,
        description:
          `Report an xgrep finding you are confident is a false positive as an issue on ` +
          `github.com/${FP_REPO} (public), so the rule can be fixed. Provide a MINIMAL, ` +
          `SELF-CONTAINED snippet written for the report that still triggers the rule — never ` +
          `paste the user's own code, names, paths, or secrets. The snippet is checked with ` +
          `xgrep first; the user then sees the exact issue and decides whether to file it.`,
        inputSchema: {
          type: "object",
          properties: {
            rule: { type: "string", description: "The finding's rule id, e.g. python-sql-injection." },
            language: { type: "string", description: "The snippet's language as xgrep names it: python, javascript, typescript, go, java, …" },
            snippet: { type: "string", description: "A minimal synthetic reproduction (a few lines) that still triggers the rule but is safe/correct code." },
            reason: { type: "string", description: "Why the finding is a false positive: what makes this code safe." },
            expected: { type: "string", description: "Optional: what the rule should do instead." },
          },
          required: ["rule", "language", "snippet", "reason"],
        },
      });
    } catch {
      // registration unavailable here — the rest of the guard still works
    }
    return next(e);
  });

  // False-positive reports: verify the reproduction, let the user review the
  // exact issue, and only then file it. Never fails the session: any error
  // becomes a "not filed" answer the agent can relay.
  on("tool.call", { tool: "mcp__secure-guard__report_false_positive" }, async ($, e, next) => {
    try {
      return { result: await reportFalsePositive($, e, next) };
    } catch (err) {
      return { result: `Not filed: secure-guard hit an error (${err?.message ?? err}).` };
    }
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
  // if there are high-confidence security findings, attach them to the tool's
  // result (withAdvisory) so Claude sees them and can fix them in the same turn.
  // `next` runs the tool exactly once (outside the scan try/catch), so any scan
  // error fails OPEN — the edit stays, we just stay quiet.
  on("tool.call", { tool: ["Write", "Edit", "MultiEdit"] }, async ($, e, next) => {
    const r = await next(e);
    if (!r || r.deny || r.isError) return r; // tool blocked or failed — nothing landed
    try {
      // Route by artifact: IaC (Terraform/Dockerfile/K8s/CFN) → cnspec policy,
      // plus xgrep for Terraform/Dockerfiles; everything else → xgrep review.
      const file = String(e.file_path ?? "");
      const kind = iacScanKind(file, await contentForRouting($, e, file));
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
    const mine = { kind: "command", command, verdict };
    await awaitDecision($, next.signal, mine, { title: "xgrep guard", rows: paneRows(verdict) });

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

// awaitDecision shows `mine` in the pane (or the band above the prompt when the
// pane can't be placed) and waits until the user presses a button, the turn is
// interrupted, or HOLD_LIMIT_MS passes; it sets mine.decision. One request is
// shown at a time; a second waits for the first. `mine.kind` picks the drawing.
async function awaitDecision($, signal, mine, { title, rows }) {
  mine.decision = null;
  mine.where = "pane";
  while (held !== null) {
    if (signal.aborted) { mine.decision = "interrupted"; return; }
    await $.process.run(["sleep", POLL], { timeoutMs: 5000 });
  }
  held = mine;
  let opened = { isPlaced: false };
  try {
    opened = await $.ui.open({ id: PANE_ID, title, focus: true, rows });
    if (!opened.isPlaced) mine.where = "band";
    $.ui.invalidate("ui.render");

    const start = await $.clock.now();
    while (mine.decision === null) {
      if (signal.aborted) { mine.decision = "interrupted"; break; }
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
}

function denyResult(why, verdict) {
  return {
    deny:
      `xgrep guard held this command and did not run it: ${why}. ` +
      `xgrep flagged ${verdict.flagged}. Do not retry it unless the user asks you to.`,
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
  const envPath = await $.env.get("XGREP_PATH"); // $.env.get resolves async
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

// contentForRouting returns the file's full content when routing needs it. A
// Write carries it; an Edit/MultiEdit carries only a fragment, so for a path
// that can only be classified by content (YAML/JSON → K8s? CFN?) read the file
// as it now stands — the edit has already landed. Unreadable → undefined, and
// the file is simply not treated as IaC (fail-open).
async function contentForRouting($, e, file) {
  if (typeof e.content === "string") return e.content;
  if (!file || !iacNeedsContent(file)) return undefined;
  try {
    return await $.fs.read(file);
  } catch {
    return undefined;
  }
}

// reviewEdit scans the file a Write/Edit/MultiEdit just touched and, if there are
// high-confidence security findings, returns the tool result augmented with them.
// `r` is what the tool itself returned (the write already happened). On anything
// uninteresting it returns `r` unchanged.
async function reviewEdit($, e, r) {
  if (!r || r.deny || r.isError) return r; // tool blocked or failed — nothing landed
  return withAdvisory(r, await codeAdvisory($, String(e.file_path ?? "")));
}

// withAdvisory attaches findings to the tool's own result as `context`, which
// the model reads right after the result (like a PostToolUse reminder). The
// result itself must stay the tool's record: core validates a hook's `result`
// against the tool's output schema, and a bare string there turns the
// successful write into a tool error the model can't act on.
function withAdvisory(r, text) {
  if (!text) return r;
  return { ...r, context: [...(r.context ?? []), text] };
}

// codeAdvisory runs the xgrep code review on one file and returns the advisory
// text, or null when the file isn't scannable, xgrep isn't here, or it's clean.
async function codeAdvisory($, file) {
  if (!file || !isScannable(file)) return null;
  const b = await ensureBackend($);
  if (b.mode === "unavailable") return null; // scanner not here — stay quiet (fail open)
  const findings = await scanFile($, b, file);
  if (!findings.length) return null;
  announceFindings($, "xgrep", findings, file);
  return `${advisoryText(file, findings)}\n${FP_HINT}`;
}

// announceFindings tells the user what the agent was just handed: advisories
// reach the model as `context`, which the transcript doesn't show, so without
// this the user sees the agent change code they didn't ask about with no
// visible reason. A transcript line (kept, right under the edit) says what
// Mondoo caught; a toast draws the eye to it.
function announceFindings($, engine, findings, file) {
  $.ui.log(findingsNotice(engine, file, findings));
  $.ui.toast(findingsToast(engine, file, findings));
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

// ─── False-positive reports ──────────────────────────────────────────────────

// reportFalsePositive answers the report_false_positive tool with the text the
// agent reads. Order matters: validate, prove the snippet reproduces, THEN show
// the user the exact issue — so they never review a report that wouldn't help
// a maintainer — and file only on their say-so. Nothing leaves the machine
// before that press.
async function reportFalsePositive($, e, next) {
  const problems = validateFpReport(e);
  if (problems.length) return `Not filed — fix the report and call again:\n- ${problems.join("\n- ")}`;
  const rule = String(e.rule).trim();
  const language = String(e.language).trim();
  const snippet = String(e.snippet);

  const b = await ensureBackend($);
  if (b.mode === "unavailable") return `Not filed: xgrep isn't available to check the reproduction (${b.reason}).`;
  const run = await $.process.run([...b.cmd, ...fpReproArgs(rule, language)], { stdin: snippet, timeoutMs: REVIEW_TIMEOUT_MS });
  const doc = parseJsonObject(run.stdout ?? "");
  if (!doc) {
    const why = String(run.stderr ?? "").trim().split("\n")[0] || `exit code ${run.exitCode}`;
    return `Not filed: xgrep could not check the snippet (${why}). Check the rule id and language.`;
  }
  if (!fpReproduces(doc, rule)) {
    return `Not filed: the snippet does not trigger ${rule}, so it wouldn't reproduce the false positive. ` +
      `Write a minimal snippet that still triggers ${rule} and call again.`;
  }

  const issue = fpIssue({ rule, language, snippet, reason: e.reason, expected: e.expected, xgrepVersion: doc.version });
  const mine = { kind: "report", rule, language, snippet, reason: String(e.reason).trim(), issue };
  await awaitDecision($, next.signal, mine, { title: "Report a false positive", rows: 18 });
  if (mine.decision !== "file") {
    const why = { cancel: "the user pressed Cancel", timeout: "no answer within 10 minutes", interrupted: "the turn was interrupted" }[mine.decision]
      ?? "the review didn't complete";
    return `Not filed: ${why}. Don't report it again unless the user asks.`;
  }
  return await fileIssue($, issue);
}

// fileIssue files with the GitHub CLI (the user's own account), with the
// false-positive label when the repo has it. Without a working `gh`, it hands
// back a prefilled link for the user to submit themselves.
async function fileIssue($, issue) {
  const create = (withLabel) => $.process.run(
    ["gh", "issue", "create", "--repo", FP_REPO, "--title", issue.title, "--body-file", "-", ...(withLabel ? ["--label", FP_LABEL] : [])],
    { stdin: issue.body, timeoutMs: 60000 },
  );
  let run;
  try {
    run = await create(true);
    if (run.exitCode !== 0 && /label/i.test(run.stderr ?? "")) run = await create(false);
  } catch (err) {
    run = { exitCode: 127, stdout: "", stderr: String(err?.message ?? err) };
  }
  const url = (String(run.stdout ?? "").match(/https:\/\/github\.com\/\S+\/issues\/\d+/) ?? [])[0];
  if (run.exitCode === 0 && url) {
    $.ui.toast(`secure-guard: filed ${url}`);
    return `Filed ${url}. Tell the user, and keep the code as it is.`;
  }
  const why = String(run.stderr ?? "").trim().split("\n")[0] || "the GitHub CLI isn't available";
  return `Not filed automatically (${why}). Give the user this link to review and submit it themselves:\n${fpIssueUrl(issue)}`;
}

// ─── cnspec (IaC policy) engine ──────────────────────────────────────────────

// ensureCnspec resolves cnspec once per session: CNSPEC_PATH → `cnspec` on PATH
// → unavailable. cnspec has no npm package, so when it is absent the IaC guard
// simply stays off (fail-open); we point the user at the install docs.
async function ensureCnspec($) {
  if (cnspecBackend) return cnspecBackend;
  const candidates = [];
  const envPath = await $.env.get("CNSPEC_PATH");
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

// reviewIac scans an IaC file the agent just wrote with cnspec — and, for
// Terraform and Dockerfiles, with xgrep too — and returns any findings as the
// tool result. The two engines run side by side and each fails open on its own:
// one missing or erroring never hides the other's findings.
async function reviewIac($, e, r, kind) {
  const file = String(e.file_path ?? "");
  if (!file) return r;
  const quiet = (leg) => (err) => {
    $.ui.log(`secure-guard: ${leg} review error (${err?.message ?? err}); not reporting`);
    return null;
  };
  const [iac, code] = await Promise.all([
    iacAdvisory($, file, kind).catch(quiet("cnspec")),
    alsoCodeScan(kind) ? codeAdvisory($, file).catch(quiet("xgrep")) : null,
  ]);
  return withAdvisory(r, combineAdvisories([iac, code]));
}

// iacAdvisory runs cnspec on one IaC file and returns the advisory text, or null
// when cnspec isn't installed or every check passed.
async function iacAdvisory($, file, kind) {
  const b = await ensureCnspec($);
  if (b.mode !== "ok") return null; // cnspec not installed — stay quiet
  const findings = await cnspecScan($, b, kind, file);
  if (!findings.length) return null;
  announceFindings($, "cnspec", findings, file);
  return iacAdvisoryText(file, kind, findings);
}

async function cnspecScan($, b, kind, file) {
  const source = cnspecPolicySource(kind, {
    CNSPEC_POLICY_BUNDLE: await $.env.get("CNSPEC_POLICY_BUNDLE"),
    CNSPEC_CONTENT_DIR: await $.env.get("CNSPEC_CONTENT_DIR"),
    CNSPEC_USE_PLATFORM: await $.env.get("CNSPEC_USE_PLATFORM"),
  });
  const notice = cnspecPolicyNotice(source);
  if (notice && !cnspecNoticeShown) {
    cnspecNoticeShown = true;
    $.ui.toast(source.kind === "platform"
      ? "secure-guard: cnspec is using your Mondoo Platform policies"
      : "secure-guard: cnspec is downloading the latest policies (nothing is uploaded)");
    $.ui.log(`secure-guard: ${notice}`);
  }
  const args = cnspecScanArgs(kind, file, source.bundles, { platform: source.kind === "platform" });
  const run = await $.process.run([...b.cmd, ...args], { timeoutMs: IAC_TIMEOUT_MS });
  const doc = parseJsonObject(run.stdout ?? "");
  return doc ? sarifFindings(doc) : [];
}

// ─── Drawing (pane / band) ───────────────────────────────────────────────────

function paneRows(v) {
  return Math.min(24, 6 + (v.lines?.length ?? 0));
}

// The pane says what it is doing — holding the call until you choose — and
// lists what xgrep flagged in its own words (not xgrep's "blocked … retry"
// summary, which is written for a hook that blocks outright).
function draw(t, state) {
  return state.kind === "report" ? drawReport(t, state) : drawCommand(t, state);
}

// drawReport previews the issue exactly as it would be filed — the user is the
// one publishing it, to a public repo.
function drawReport(t, state) {
  const { Box, Text, Button } = t;
  const decide = (choice) => () => { if (state.decision === null) state.decision = choice; };
  const shown = state.snippet.replace(/\s+$/, "").split("\n");
  const snippet = shown.slice(0, 8).map((line, i) => Text({ key: `s${i}`, wrap: "truncate-end", children: `  ${line}` }));
  if (shown.length > 8) snippet.push(Text({ key: "more", dimColor: true, children: `  … ${shown.length - 8} more line(s)` }));
  const row = (key, label, value) => Text({ key, wrap: "truncate-end", children: [Text({ dimColor: true, children: label }), Text({ children: value })] });
  return Box({
    flexDirection: "column",
    borderStyle: "round",
    borderColor: "cyan",
    paddingX: 1,
    children: [
      Text({ key: "title", children: [
        Text({ bold: true, color: "cyan", children: "Report a false positive " }),
        Text({ dimColor: true, children: `to github.com/${FP_REPO} (public)` }),
      ] }),
      row("t", "Title    ", state.issue.title),
      row("r", "Why      ", state.reason.split("\n")[0]),
      Text({ key: "rh", dimColor: true, children: "Repro    (checked: still triggers the rule)" }),
      Box({ key: "snip", flexDirection: "column", children: snippet }),
      Box({
        key: "buttons",
        marginTop: 1,
        gap: 2,
        children: [
          Button({ key: "file", label: "File issue", hotkey: "1", plain: true, onPress: decide("file") }),
          Button({ key: "cancel", label: "Cancel", hotkey: "2", plain: true, autoFocus: true, onPress: decide("cancel") }),
          Text({ key: "hint", dimColor: true, children: "nothing is sent unless you file it" }),
        ],
      }),
    ],
  });
}

function drawCommand(t, state) {
  const { Box, Text, Button } = t;
  const { verdict } = state;
  const list = (verdict.lines?.length ? verdict.lines : [verdict.flagged]).map((line, i) =>
    Text({
      key: `l${i}`,
      wrap: "truncate-end",
      children: [
        Text({ dimColor: true, children: i === 0 ? "Flagged  " : "         " }),
        Text({ color: "red", bold: true, children: line }),
      ],
    })
  );
  const decide = (choice) => () => { if (state.decision === null) state.decision = choice; };
  return Box({
    flexDirection: "column",
    borderStyle: "round",
    borderColor: "yellow",
    paddingX: 1,
    children: [
      Text({ key: "title", children: [
        Text({ bold: true, color: "yellow", children: "⚠ xgrep guard " }),
        Text({ dimColor: true, children: "held this command until you decide" }),
      ] }),
      Text({ key: "cmd", children: [Text({ dimColor: true, children: "Command  " }), Text({ bold: true, children: state.command })], wrap: "truncate-end" }),
      Box({ key: "list", flexDirection: "column", children: list }),
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
