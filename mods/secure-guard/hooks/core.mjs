// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// secure-guard core — the agent-neutral logic shared by every adapter
// (the Claude mod, the Codex/Vibe hook command, the Pi/opencode extensions).
//
// Everything here is PURE: parsing, filtering, routing, version comparison,
// cnspec bundle mapping, and advisory formatting. There is NO I/O and no
// dependency on any agent API — each adapter spawns xgrep/cnspec itself (with
// its own runtime) and calls these functions to decide and format. That keeps
// one implementation of "what counts as a finding and how we phrase it" across
// all agents.
//
// The two engines this drives:
//   xgrep  — secrets/PII + dangerous-command guard (via `xgrep guard --command`,
//            parsed by normalizeVerdict) AND OWASP Top 10 code review (via
//            `xgrep scan --json`, filtered by highConfidenceFindings).
//   cnspec — IaC policy checks (via `cnspec scan … -o sarif`, parsed by
//            sarifFindings), with the policy source chosen by cnspecPolicySource.
//
// Terraform and Dockerfiles go to BOTH engines: cnspec for policy, xgrep for the
// secrets and code issues cnspec doesn't look for (a hard-coded key in main.tf).

// ─── Shared constants ────────────────────────────────────────────────────────

export const XGREP_NPM = "@mondoohq/xgrep"; // public package — the fetch/install source
// Pinned to a tested release so a session can't pull up an unvetted build.
export const XGREP_PIN = "0.80.0";
// Minimum xgrep the guard needs: `xgrep guard --command` landed in 0.78.0.
export const XGREP_MIN = "0.78.0";

export const CNSPEC_INSTALL_URL = "https://mondoo.com/docs/cnspec/install";

// A cnspec IaC scan loads several bundles and compiles MQL — a real one takes
// ~20–30s — so the budget is generous: a timeout fails open, silently, and must
// not hit an ordinary slow scan. Shared by the mod and every adapter.
export const IAC_TIMEOUT_MS = 90000;

// IaC kinds that also get the xgrep code scan. Terraform and Dockerfiles are
// where secrets get hard-coded; K8s/CFN YAML is left to cnspec alone.
const IAC_ALSO_CODE = new Set(["terraform", "docker"]);

// cnspec runs a policy only when one of its filters matches the IaC asset. The
// public content bundles are platform/provider scoped, so the guard loads a set
// per target (cnspec accepts multiple `-f`; non-matching bundles are skipped).
// `terraform-deprecations` matches ANY terraform-hcl, so it guarantees at least
// one policy runs and no "asset doesn't support any policies" error.
export const CNSPEC_CONTENT_RAW = "https://raw.githubusercontent.com/mondoohq/cnspec/main/content";
export const CNSPEC_BUNDLES = {
  terraform: ["terraform-deprecations", "mondoo-aws-security", "mondoo-azure-security", "mondoo-gcp-security"],
  docker: ["mondoo-dockerfile-security", "mondoo-dockerfile-best-practices"],
  k8s: ["mondoo-kubernetes-security", "mondoo-kubernetes-best-practices"],
  cloudformation: ["mondoo-aws-security"],
};

// Inline review skips files that are not code worth scanning.
export const REVIEW_SKIP_EXT = new Set([
  ".md", ".markdown", ".txt", ".rst", ".json", ".lock", ".sum", ".mod",
  ".yaml", ".yml", ".toml", ".ini", ".cfg", ".csv", ".tsv", ".svg", ".png",
  ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".ico", ".lockb",
]);
const REVIEW_SKIP_DIRS = new Set(["node_modules", ".git", "vendor", "dist"]);
const REVIEW_MAX_SHOWN = 10;

// ─── xgrep: version resolution helpers ───────────────────────────────────────

// parseVersion pulls an x.y.z out of `xgrep version` output; null if absent.
export function parseVersion(out) {
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(String(out ?? ""));
  return m ? `${m[1]}.${m[2]}.${m[3]}` : null;
}

// meetsMin reports whether a parsed version is >= XGREP_MIN. An unparseable
// version counts as too old, so the guard prefers a known-good release.
export function meetsMin(version) {
  return version != null && cmpSemver(version, XGREP_MIN) >= 0;
}

// cmpSemver compares two x.y.z strings and returns -1, 0, or 1.
export function cmpSemver(a, b) {
  const pa = String(a).split(".").map(Number);
  const pb = String(b).split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

// ─── xgrep: shell verdict ────────────────────────────────────────────────────

// normalizeVerdict maps a `xgrep guard --command` JSON verdict
// ({decision, summary, findings[]}) to { decision, summary, lines, flagged }.
//
// `summary` is xgrep's own ready-made message, written for a hook that blocks
// outright ("xgrep guard blocked this action … remove … and retry"); the
// pre-tool adapters, which do block, pass it on. A guard that HOLDS the call
// for the user must not echo it — nothing was blocked yet — so `lines` (one per
// finding, for a list) and `flagged` (one line, for a sentence) are phrased
// here from the structured findings instead.
export function normalizeVerdict(v) {
  const findings = Array.isArray(v?.findings) ? v.findings : [];
  const decision = v?.decision ?? (findings.length ? "ask" : "allow");
  const summary = v?.summary ?? (findings.length ? `${findings.length} finding(s)` : "");
  const named = findings.map(findingName);
  const lines = findings.map((f, i) => {
    const sev = String(f?.severity ?? "").trim().toUpperCase();
    return sev ? `${sev} · ${named[i]}` : named[i];
  });
  const flagged = named.length
    ? named.join("; ")
    : firstLine(summary).replace(/[:.]+$/, "") || "a risky command";
  return { decision, summary, lines, flagged };
}

// findingName is how one guard finding reads to a person: its title, then the
// rule id that lets them (or the agent) look it up.
function findingName(f) {
  const title = String(f?.title ?? "").trim();
  const rule = String(f?.rule ?? "").trim();
  if (title && rule && rule !== title) return `${title} (${rule})`;
  return title || rule || "finding";
}

function firstLine(s) {
  return String(s ?? "").trim().split("\n")[0].trim();
}

// ─── xgrep: code review ──────────────────────────────────────────────────────

// highConfidenceFindings: given a parsed `xgrep scan --json` document, return the
// high-confidence security findings — filtered on the rule's `confidence` (HIGH),
// dropping test/fixture scope.
export function highConfidenceFindings(doc) {
  const results = Array.isArray(doc?.results) ? doc.results : [];
  return results
    .filter((m) => m?.extra?.confidence === "HIGH" && m?.extra?.scope !== "test")
    .map((m) => ({
      rule: m.check_id ?? "finding",
      title: m.extra?.title ?? m.check_id ?? "finding",
      line: m.start?.line ?? 0,
      message: firstSentence(m.extra?.message ?? ""),
    }));
}

// advisoryText phrases xgrep code findings for the agent. `written` says which
// side of the write the adapter runs on: the Claude mod reviews after the file
// landed (advisory); the pre-write adapters block it, so the agent must fix the
// content and write it again — "File written." would tell it the opposite.
export function advisoryText(file, findings, { written = true } = {}) {
  const head = written
    ? `File written. xgrep flagged ${findings.length} high-confidence security ` +
      `issue(s) in ${file} that you should fix before continuing:`
    : `Not written: xgrep flagged ${findings.length} high-confidence security ` +
      `issue(s) in ${file}. Fix them and write the file again:`;
  const shown = findings.slice(0, REVIEW_MAX_SHOWN);
  const body = shown
    .map((f) => `  • ${f.title} (${f.rule}), line ${f.line}: ${f.message}`)
    .join("\n");
  const more = findings.length > shown.length
    ? `\n  … and ${findings.length - shown.length} more.`
    : "";
  return `${head}\n${body}${more}`;
}

// isScannable keeps inline review on actual code: no docs/data/lockfiles, no
// vendored or VCS trees, no dotfiles. xgrep decides the language from here.
export function isScannable(file) {
  const segs = file.split(/[\\/]/); // tolerate both / and \ (Windows paths)
  const base = segs[segs.length - 1] ?? "";
  if (base === "" || base.startsWith(".")) return false;
  if (segs.some((s) => REVIEW_SKIP_DIRS.has(s))) return false;
  const dot = base.lastIndexOf(".");
  const ext = dot > 0 ? base.slice(dot).toLowerCase() : "";
  if (REVIEW_SKIP_EXT.has(ext)) return false;
  return true;
}

// firstSentence trims a long message to its first sentence.
export function firstSentence(msg) {
  const s = String(msg).trim();
  const end = s.indexOf(". ");
  return end > 0 ? s.slice(0, end + 1) : s;
}

// ─── cnspec: IaC routing, bundles, SARIF ─────────────────────────────────────

// iacScanKind maps a written file to a cnspec scan target, or null. Terraform
// and Dockerfile are unambiguous by path; k8s and CloudFormation YAML/JSON are
// classified from content (available on Write).
export function iacScanKind(file, content) {
  const base = (file.split(/[\\/]/).pop() ?? "").toLowerCase();
  if (base === "") return null;
  if (base.endsWith(".tf") || base.endsWith(".tf.json")) return "terraform";
  if (base === "dockerfile" || base === "containerfile" || base.endsWith(".dockerfile")) return "docker";
  if (base.endsWith(".yaml") || base.endsWith(".yml") || base.endsWith(".json")) {
    return classifyYaml(content);
  }
  return null;
}

// alsoCodeScan reports whether an IaC kind also gets the xgrep code scan.
export function alsoCodeScan(kind) {
  return IAC_ALSO_CODE.has(kind);
}

// iacNeedsContent reports whether iacScanKind can only classify this path from
// its content (YAML/JSON could be K8s, CloudFormation, or neither). An adapter
// whose event carries no full content (Edit/MultiEdit) reads the file for these.
export function iacNeedsContent(file) {
  const base = (String(file ?? "").split(/[\\/]/).pop() ?? "").toLowerCase();
  if (base.endsWith(".tf.json")) return false; // terraform by path
  return base.endsWith(".yaml") || base.endsWith(".yml") || base.endsWith(".json");
}

// classifyYaml tells a Kubernetes manifest from a CloudFormation template by
// content; null when it is neither (or content is unavailable).
export function classifyYaml(content) {
  if (typeof content !== "string" || content === "") return null;
  if (/AWSTemplateFormatVersion|^\s*Resources:\s*$/m.test(content) && /\bType:\s*["']?AWS::/.test(content)) return "cloudformation";
  if (/^\s*apiVersion:\s/m.test(content) && /^\s*kind:\s/m.test(content)) return "k8s";
  return null;
}

// cnspecScanArgs builds the `cnspec scan …` argv for one IaC file. The docker
// provider scans a Dockerfile as `scan docker file <path>`; the others take the
// path directly.
//
// By default the scan runs --incognito against the given bundles: cnspec
// evaluates the file on this machine, reports nothing anywhere, and skips the
// Mondoo Platform config so a broken/absent credential never breaks the guard.
// With { platform: true } it instead runs the policies assigned in the user's
// logged-in Mondoo Platform space (no -f, no --incognito); cnspec then reports
// the scan's results to that space — which is why it is opt-in.
export function cnspecScanArgs(kind, file, bundles, opts = {}) {
  const target = kind === "docker" ? ["docker", "file", file] : [kind, file];
  if (opts.platform) return ["scan", ...target, "-o", "sarif"];
  const policy = (Array.isArray(bundles) ? bundles : []).flatMap((b) => ["-f", b]);
  return ["scan", ...target, ...policy, "--incognito", "-o", "sarif"];
}

// cnspecPolicySource decides where the IaC policies come from, from the
// adapter's environment ({ CNSPEC_POLICY_BUNDLE, CNSPEC_CONTENT_DIR,
// CNSPEC_USE_PLATFORM }), in precedence:
//   1. CNSPEC_POLICY_BUNDLE — explicit bundle(s), incognito
//   2. CNSPEC_CONTENT_DIR   — a local cnspec content checkout, incognito, offline
//   3. CNSPEC_USE_PLATFORM  — the logged-in Mondoo Platform space's policies
//   4. the latest public bundles, downloaded from GitHub, incognito
// Returns { kind: "bundles"|"platform", bundles, remote } where `remote` is true
// when cnspec will download policy bundles (policies come down; no file content
// goes up). An adapter turns `kind`/`remote` into a one-time notice.
export function cnspecPolicySource(kind, env = {}) {
  const override = String(env.CNSPEC_POLICY_BUNDLE ?? "").trim();
  const contentDir = String(env.CNSPEC_CONTENT_DIR ?? "").trim();
  if (!override && !contentDir && isTruthy(env.CNSPEC_USE_PLATFORM)) {
    return { kind: "platform", bundles: [], remote: false };
  }
  const bundles = cnspecBundlesFor(kind, override, contentDir);
  return { kind: "bundles", bundles, remote: bundles.some(isRemoteBundle) };
}

function isTruthy(v) {
  return /^(1|true|yes|on)$/i.test(String(v ?? "").trim());
}

function isRemoteBundle(b) {
  return /^(https?|s3):\/\//i.test(b);
}

// cnspecPolicyNotice is the one line an adapter shows the first time a session
// runs cnspec, so the policy download (or the Platform reporting) is never
// silent. null when the scan neither downloads nor reports anything.
export function cnspecPolicyNotice(source) {
  if (source?.kind === "platform") {
    return "cnspec is running your Mondoo Platform space's assigned IaC policies " +
      "(CNSPEC_USE_PLATFORM); it reports scan results to that space.";
  }
  if (source?.remote) {
    return "cnspec is downloading the latest policy bundles for IaC checks. Only " +
      "policies are downloaded: your files are assessed on this machine and " +
      "nothing is uploaded. Set CNSPEC_CONTENT_DIR to a local cnspec content " +
      "checkout to work offline.";
  }
  return null;
}

// cnspecBundlesFor resolves the `-f` policy sources for an IaC kind, in
// precedence: CNSPEC_POLICY_BUNDLE (comma-separated override) → a local cnspec
// content checkout (contentDir) → the public raw content URLs.
export function cnspecBundlesFor(kind, override, contentDir) {
  if (override && override.trim()) {
    return override.split(",").map((s) => s.trim()).filter(Boolean);
  }
  const names = CNSPEC_BUNDLES[kind] || [];
  if (contentDir && contentDir.trim()) {
    const base = contentDir.trim().replace(/\/+$/, "");
    return names.map((n) => `${base}/${n}.mql.yaml`);
  }
  return names.map((n) => `${CNSPEC_CONTENT_RAW}/${n}.mql.yaml`);
}

// extractJsonObject returns the first complete top-level {…} object in s, or
// null. It scans balanced braces, skipping any inside JSON strings, so a
// scanner that writes a log/progress/summary line AROUND the JSON on stdout
// (cnspec can) doesn't break the parse. The callers already skipped a leading
// prefix with indexOf("{"); this also bounds the suffix, so trailing text no
// longer makes JSON.parse throw and silently drop real findings (fail-open).
export function extractJsonObject(s) {
  const str = String(s ?? "");
  const start = str.indexOf("{");
  if (start < 0) return null;
  let depth = 0, inStr = false, esc = false;
  for (let i = start; i < str.length; i++) {
    const c = str[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') inStr = true;
    else if (c === "{") depth++;
    else if (c === "}" && --depth === 0) return str.slice(start, i + 1);
  }
  return null; // unbalanced — no complete object
}

// parseJsonObject extracts and parses the first top-level JSON object in s,
// returning the parsed value or null. It NEVER throws, so a cnspec call site
// doesn't rely on a distant outer try/catch to stay fail-open.
export function parseJsonObject(s) {
  const obj = extractJsonObject(s);
  if (obj == null) return null;
  try { return JSON.parse(obj); } catch { return null; }
}

// sarifFindings extracts failed policy checks from a SARIF document. It drops
// cnspec's `asset-error` results (the scan could not evaluate → stay quiet) and
// keeps only FAILED checks (cnspec marks passes kind:"pass"/level:"none").
export function sarifFindings(doc) {
  const runs = Array.isArray(doc?.runs) ? doc.runs : [];
  const out = [];
  for (const run of runs) {
    for (const res of Array.isArray(run?.results) ? run.results : []) {
      const rule = res?.ruleId ?? "policy-check";
      if (rule === "asset-error") continue;
      const failed = res?.kind === "fail" ||
        (res?.kind == null && ["error", "warning"].includes(res?.level));
      if (!failed) continue;
      // cnspec encodes "<title>: FAIL · <sev> · score n/100" — keep the title.
      const title = String(res?.message?.text ?? "").split(/:\s+(?:PASS|FAIL)\b/i)[0].trim();
      out.push({
        rule,
        level: res?.level ?? "warning",
        severity: res?.properties?.severity ?? "",
        message: firstSentence(title),
      });
    }
  }
  return out;
}

// combineAdvisories joins the advisories from both engines into one tool result
// (null when there are none). Only the first keeps its "File written." /
// "Not written:" lead.
export function combineAdvisories(texts) {
  const parts = (Array.isArray(texts) ? texts : []).filter((t) => typeof t === "string" && t !== "");
  if (parts.length === 0) return null;
  return parts.map((t, i) => (i === 0 ? t : t.replace(/^(?:File written\.|Not written:) /, ""))).join("\n\n");
}

export function iacAdvisoryText(file, kind, findings, { written = true } = {}) {
  const head = written
    ? `File written. cnspec policy found ${findings.length} issue(s) in ${file} ` +
      `(${kind}) to fix before continuing:`
    : `Not written: cnspec policy found ${findings.length} issue(s) in ${file} ` +
      `(${kind}). Fix them and write the file again:`;
  const shown = findings.slice(0, REVIEW_MAX_SHOWN);
  const body = shown
    .map((f) => `  • ${f.severity ? `[${f.severity}] ` : ""}${f.message} (${f.rule})`)
    .join("\n");
  const more = findings.length > shown.length
    ? `\n  … and ${findings.length - shown.length} more.`
    : "";
  return `${head}\n${body}${more}`;
}

// ─── False-positive reports ──────────────────────────────────────────────────
//
// When the agent is confident an xgrep finding is a false positive, it can
// report it as an issue on this repo so the rule gets adjusted. A report must be
// actionable: a MINIMAL, SELF-CONTAINED snippet that still triggers the rule
// (verified with `xgrep scan --stdin` before anything is filed), the rule id,
// the xgrep version, and why the finding is wrong. The repo is public, so the
// snippet must be written for the report — never the user's own code — and
// the user sees the exact issue and confirms before it is filed.

export const FP_REPO = "mondoohq/secure-stack";
export const FP_LABEL = "false-positive";
const FP_MAX_SNIPPET_LINES = 60;
const FP_MAX_SNIPPET_CHARS = 4000;
const FP_MAX_REASON_CHARS = 2000;

// validateFpReport checks the agent's input; returns a list of problems, each
// phrased so the agent can fix its call (empty = valid).
export function validateFpReport(input) {
  const problems = [];
  const rule = String(input?.rule ?? "").trim();
  const language = String(input?.language ?? "").trim();
  const snippet = String(input?.snippet ?? "");
  const reason = String(input?.reason ?? "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(rule)) problems.push("`rule` must be the finding's rule id, e.g. python-sql-injection");
  if (!/^[A-Za-z0-9#+_-]+$/.test(language)) problems.push("`language` must be the snippet's language as xgrep names it, e.g. python, javascript, go");
  if (snippet.trim() === "") problems.push("`snippet` must be a minimal, self-contained reproduction");
  else if (snippet.length > FP_MAX_SNIPPET_CHARS || snippet.split("\n").length > FP_MAX_SNIPPET_LINES) {
    problems.push(`\`snippet\` must be minimal: at most ${FP_MAX_SNIPPET_LINES} lines and ${FP_MAX_SNIPPET_CHARS} characters`);
  }
  if (reason === "") problems.push("`reason` must say why the finding is a false positive");
  else if (reason.length > FP_MAX_REASON_CHARS) problems.push(`\`reason\` must be at most ${FP_MAX_REASON_CHARS} characters`);
  return problems;
}

// fpReproArgs is the xgrep argv that checks the snippet (on stdin) still
// triggers the rule — the same command the issue tells a maintainer to run.
export function fpReproArgs(rule, language) {
  return ["scan", "--stdin", "--lang", language, "--rule-id", rule, "--json"];
}

// fpReproduces reports whether a parsed `xgrep scan --json` result holds a
// finding for `rule`.
export function fpReproduces(doc, rule) {
  const results = Array.isArray(doc?.results) ? doc.results : [];
  return results.some((m) => m?.check_id === rule);
}

// fpIssue renders the issue title and body. The code fence is longer than any
// run of backticks in the snippet, so a snippet can't break out of it.
export function fpIssue({ rule, language, snippet, reason, expected, xgrepVersion }) {
  const longest = Math.max(0, ...(String(snippet).match(/`+/g) ?? []).map((r) => r.length));
  const fence = "`".repeat(Math.max(3, longest + 1));
  const title = `False positive: ${rule} (${language})`;
  const body = [
    `**Rule:** \`${rule}\`  `,
    `**Language:** ${language}  `,
    `**xgrep:** ${xgrepVersion || "unknown"}`,
    "",
    "### Reproduction",
    "",
    `${fence}${language}`,
    String(snippet).replace(/\s+$/, ""),
    fence,
    "",
    `\`xgrep ${fpReproArgs(rule, language).join(" ")} < repro\` reports \`${rule}\` on this snippet (checked before filing).`,
    "",
    "### Why this is a false positive",
    "",
    String(reason).trim(),
    ...(String(expected ?? "").trim() ? ["", "### Expected", "", String(expected).trim()] : []),
    "",
    "---",
    "Reported from the secure-guard mod after the user reviewed it. The snippet is a minimal reproduction written for this report.",
  ].join("\n");
  return { title, body };
}

// fpIssueUrl is the prefilled new-issue link — the fallback when the GitHub CLI
// can't file it. Nothing is sent until the user opens the link and submits.
export function fpIssueUrl({ title, body }) {
  const q = new URLSearchParams({ title, body, labels: FP_LABEL });
  return `https://github.com/${FP_REPO}/issues/new?${q.toString()}`;
}

// ─── What the user sees when findings go to the agent ────────────────────────

const NOTICE_MAX_SHOWN = 3;

// findingsNotice is the transcript line telling the user that a Mondoo scanner
// caught something and handed it to the agent. Advisories reach the model as
// hidden context, so this line is how the user sees what was caught and why the
// agent is about to touch code they didn't ask about. `engine` is "xgrep"
// (code findings: { rule, title, line }) or "cnspec" (policy findings:
// { rule, severity, message }).
export function findingsNotice(engine, file, findings) {
  const list = Array.isArray(findings) ? findings : [];
  const name = (f) => engine === "cnspec"
    // A cnspec finding has no separate title: sarifFindings already cut its
    // `message` down to the check's title ("<title>: FAIL · …" → "<title>"),
    // so `message` is the human name here, as `title` is for xgrep.
    ? `${f?.severity ? `${String(f.severity).toUpperCase()} ` : ""}${f?.message || f?.rule || "policy check"} (${f?.rule ?? "policy"})`
    : `${f?.title || f?.rule || "finding"} (${f?.rule ?? "finding"})${f?.line ? `, line ${f.line}` : ""}`;
  const shown = list.slice(0, NOTICE_MAX_SHOWN).map(name).join("; ");
  const more = list.length > NOTICE_MAX_SHOWN ? `; and ${list.length - NOTICE_MAX_SHOWN} more` : "";
  return `${foundLead(engine, file, list.length)}: ${shown}${more}. Sent to Claude to address.`;
}

// findingsToast is the short cue for the same event; it shares findingsNotice's
// lead so the two can't drift apart.
export function findingsToast(engine, file, findings) {
  const n = Array.isArray(findings) ? findings.length : 0;
  return `${foundLead(engine, file, n)} — sent to Claude`;
}

// foundLead: "Mondoo xgrep found 1 issue in app.py".
function foundLead(engine, file, n) {
  const base = String(file ?? "").split(/[\\/]/).pop() || "the file";
  return `Mondoo ${engine} found ${n} issue${n === 1 ? "" : "s"} in ${base}`;
}
