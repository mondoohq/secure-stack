// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for the pure inline-review logic (no scanner, no `$`): the JSON
// filter, the path gate, the message trimming, and the advisory rendering.
// Run with `node --test hooks/*.test.mjs`.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  highConfidenceFindings,
  advisoryText,
  isScannable,
  firstSentence,
  parseVersion,
  meetsMin,
  cmpSemver,
  iacScanKind,
  classifyYaml,
  sarifFindings,
  iacAdvisoryText,
  cnspecScanArgs,
  cnspecBundlesFor,
  extractJsonObject,
  parseJsonObject,
  normalizeVerdict,
  alsoCodeScan,
  iacNeedsContent,
  cnspecPolicySource,
  cnspecPolicyNotice,
  combineAdvisories,
  FP_REPO, FP_LABEL, validateFpReport, fpReproArgs, fpReproduces, fpIssue, fpIssueUrl,
  findingsNotice, findingsToast,
  parseUpdateNotice, npmGlobalPrefix, xgrepUpdateArgv, parseVersionJSON,
} from "./core.mjs";

test("cnspecScanArgs builds argv with one -f per bundle; docker uses `file`; incognito", () => {
  assert.deepEqual(cnspecScanArgs("terraform", "main.tf", []), ["scan", "terraform", "main.tf", "--incognito", "-o", "sarif"]);
  assert.deepEqual(cnspecScanArgs("docker", "Dockerfile", []), ["scan", "docker", "file", "Dockerfile", "--incognito", "-o", "sarif"]);
  assert.deepEqual(cnspecScanArgs("k8s", "d.yaml", ["a.yaml", "b.yaml"]),
    ["scan", "k8s", "d.yaml", "-f", "a.yaml", "-f", "b.yaml", "--incognito", "-o", "sarif"]);
});

test("cnspecBundlesFor: override → content dir → public URLs", () => {
  // explicit override (comma-separated) wins
  assert.deepEqual(cnspecBundlesFor("terraform", "x.yaml, y.yaml", "/ignored"), ["x.yaml", "y.yaml"]);
  // local content dir → local paths
  assert.deepEqual(cnspecBundlesFor("docker", "", "/c/"),
    ["/c/mondoo-dockerfile-security.mql.yaml", "/c/mondoo-dockerfile-best-practices.mql.yaml"]);
  // default → public raw URLs, terraform includes the universal deprecations bundle
  const tf = cnspecBundlesFor("terraform", "", "");
  assert.ok(tf[0].endsWith("/terraform-deprecations.mql.yaml"));
  assert.ok(tf.every((u) => u.startsWith("https://raw.githubusercontent.com/mondoohq/cnspec/main/content/")));
  assert.equal(cnspecBundlesFor("cloudformation", "", "").length, 1);
  assert.deepEqual(cnspecBundlesFor("unknown-kind", "", ""), []);
});

test("sarifFindings drops cnspec asset-error results (fail-open, not a finding)", () => {
  const doc = { runs: [{ results: [
    { ruleId: "asset-error", level: "error", kind: "fail", message: { text: "asset doesn't support any policies" } },
    { ruleId: "real-check", level: "error", kind: "fail", message: { text: "Bad config." } },
  ] }] };
  const got = sarifFindings(doc);
  assert.equal(got.length, 1);
  assert.equal(got[0].rule, "real-check");
});

test("iacScanKind routes Terraform and Dockerfile by path", () => {
  assert.equal(iacScanKind("main.tf"), "terraform");
  assert.equal(iacScanKind("infra/network.tf.json"), "terraform");
  assert.equal(iacScanKind("Dockerfile"), "docker");
  assert.equal(iacScanKind("build/api.dockerfile"), "docker");
  assert.equal(iacScanKind("Containerfile"), "docker");
  assert.equal(iacScanKind("app.py"), null); // code → xgrep, not cnspec
  assert.equal(iacScanKind("data.yaml"), null); // ambiguous yaml, no content → not IaC
});

test("iacScanKind classifies k8s / CloudFormation YAML from content", () => {
  const k8s = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\n";
  assert.equal(iacScanKind("deploy.yaml", k8s), "k8s");
  const cfn = "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  B:\n    Type: AWS::S3::Bucket\n";
  assert.equal(iacScanKind("stack.yaml", cfn), "cloudformation");
  assert.equal(iacScanKind("config.yaml", "foo: bar\n"), null); // neither
});

test("classifyYaml is total on empty/unknown input", () => {
  assert.equal(classifyYaml(undefined), null);
  assert.equal(classifyYaml(""), null);
  assert.equal(classifyYaml("just: data"), null);
});

test("sarifFindings keeps only failures, strips the cnspec suffix, carries severity", () => {
  const doc = {
    runs: [{
      results: [
        // cnspec failure: kind:fail, level:error, severity in properties, "FAIL · …" suffix
        { ruleId: "rds-public", level: "error", kind: "fail",
          properties: { severity: "CRITICAL" },
          message: { text: "Ensure RDS is not publicly accessible: FAIL · CRITICAL · score 0/100" } },
        // cnspec pass: must be dropped
        { ruleId: "sg-restricted", level: "none", kind: "pass",
          message: { text: "Ensure security groups restrict traffic: PASS · NONE · score 100/100" } },
        // plain SARIF (no kind) with an error level: kept
        { ruleId: "plain", level: "warning", message: { text: "Something risky." } },
      ],
    }],
  };
  const got = sarifFindings(doc);
  assert.equal(got.length, 2); // the pass is dropped
  assert.deepEqual(got[0], { rule: "rds-public", level: "error", severity: "CRITICAL", message: "Ensure RDS is not publicly accessible" });
  assert.equal(got[1].rule, "plain");
});

test("sarifFindings is total on malformed SARIF", () => {
  assert.deepEqual(sarifFindings(undefined), []);
  assert.deepEqual(sarifFindings({}), []);
  assert.deepEqual(sarifFindings({ runs: [{}] }), []);
});

test("iacAdvisoryText names the file, kind, count, and bullets with severity", () => {
  const out = iacAdvisoryText("main.tf", "terraform", [
    { rule: "r1", level: "error", severity: "CRITICAL", message: "Bad config" },
    { rule: "r2", level: "warning", severity: "", message: "Also bad" },
  ]);
  assert.match(out, /^File written\. cnspec policy found 2 issue\(s\) in main\.tf \(terraform\)/);
  assert.match(out, /• \[CRITICAL\] Bad config \(r1\)/);
  assert.match(out, /• Also bad \(r2\)/);
});

test("parseVersion extracts x.y.z from `xgrep version` output", () => {
  assert.equal(parseVersion("xgrep 0.80.0 (commit: 241337422, built: …)"), "0.80.0");
  assert.equal(parseVersion("xgrep 0.65.0 (commit: abc)\n\n⚠ update available"), "0.65.0");
  assert.equal(parseVersion("xgrep v1.2.3"), "1.2.3");
  assert.equal(parseVersion("no version here"), null);
  assert.equal(parseVersion(undefined), null);
});

test("cmpSemver orders versions", () => {
  assert.equal(cmpSemver("0.80.0", "0.78.0"), 1);
  assert.equal(cmpSemver("0.78.0", "0.80.0"), -1);
  assert.equal(cmpSemver("0.78.0", "0.78.0"), 0);
  assert.equal(cmpSemver("1.0.0", "0.99.99"), 1);
  assert.equal(cmpSemver("0.9.0", "0.10.0"), -1); // numeric, not lexical
});

test("meetsMin gates on the 0.84.0 floor (every --command leg, the new rules)", () => {
  assert.equal(meetsMin("0.85.0"), true);
  assert.equal(meetsMin("0.84.0"), true); // the floor itself
  assert.equal(meetsMin("0.83.0"), false);
  assert.equal(meetsMin("0.80.0"), false);
  assert.equal(meetsMin("0.77.0"), false); // predates --command
  assert.equal(meetsMin("0.65.0"), false);
  assert.equal(meetsMin(null), false); // unparseable → treat as too old
});

test("highConfidenceFindings keeps only HIGH-confidence, non-test findings", () => {
  const doc = {
    results: [
      { check_id: "python-code-injection", start: { line: 3 }, extra: { confidence: "HIGH", title: "Code injection", message: "Untrusted input reaches eval. Do not." } },
      { check_id: "low-conf", start: { line: 9 }, extra: { confidence: "MEDIUM", title: "Maybe", message: "Perhaps." } },
      { check_id: "in-a-test", start: { line: 1 }, extra: { confidence: "HIGH", scope: "test", title: "Test finding", message: "In a fixture." } },
    ],
  };
  const got = highConfidenceFindings(doc);
  assert.equal(got.length, 1);
  assert.deepEqual(got[0], {
    rule: "python-code-injection",
    title: "Code injection",
    line: 3,
    message: "Untrusted input reaches eval.",
  });
});

test("highConfidenceFindings is total on malformed input", () => {
  assert.deepEqual(highConfidenceFindings(undefined), []);
  assert.deepEqual(highConfidenceFindings({}), []);
  assert.deepEqual(highConfidenceFindings({ results: "nope" }), []);
  assert.deepEqual(highConfidenceFindings({ results: [{}] }), []); // no extra → dropped
});

test("highConfidenceFindings fills sensible defaults when fields are missing", () => {
  const got = highConfidenceFindings({ results: [{ extra: { confidence: "HIGH" } }] });
  assert.equal(got.length, 1);
  assert.equal(got[0].rule, "finding");
  assert.equal(got[0].title, "finding");
  assert.equal(got[0].line, 0);
  assert.equal(got[0].message, "");
});

test("isScannable skips docs, data, lockfiles, vendored trees, and dotfiles", () => {
  for (const f of ["app.py", "main.go", "src/index.ts", "lib/x.rb", "Server.java"]) {
    assert.equal(isScannable(f), true, f);
  }
  for (const f of [
    "README.md", "data.json", "go.sum", "package-lock.json", "config.yaml",
    ".env", "/x/.gitignore", "node_modules/pkg/a.js", "vendor/a.go", "dist/b.js",
  ]) {
    assert.equal(isScannable(f), false, f);
  }
});

test("firstSentence trims to the first sentence", () => {
  assert.equal(firstSentence("One thing. Two thing. Three."), "One thing.");
  assert.equal(firstSentence("No period here"), "No period here");
  assert.equal(firstSentence("  spaced out. tail"), "spaced out.");
  assert.equal(firstSentence(""), "");
});

test("advisoryText names the file, counts, and bullets each finding", () => {
  const out = advisoryText("app.py", [
    { rule: "python-code-injection", title: "Code injection", line: 3, message: "Bad." },
    { rule: "sqli", title: "SQL injection", line: 7, message: "Also bad." },
  ]);
  assert.match(out, /^File written\./);
  assert.match(out, /2 high-confidence security issue\(s\) in app\.py/);
  assert.match(out, /• Code injection \(python-code-injection\), line 3: Bad\./);
  assert.match(out, /• SQL injection \(sqli\), line 7: Also bad\./);
  assert.doesNotMatch(out, /… and/);
});

test("advisoryText caps the list and reports the remainder", () => {
  const many = Array.from({ length: 13 }, (_, i) => ({
    rule: `r${i}`, title: `T${i}`, line: i, message: "m",
  }));
  const out = advisoryText("big.py", many);
  assert.match(out, /13 high-confidence/);
  assert.match(out, /… and 3 more\.$/);
  assert.equal((out.match(/•/g) || []).length, 10);
});

// extractJsonObject: a scanner may print log/progress/summary lines AROUND the
// JSON on stdout. The old `slice(indexOf("{"))` skipped a leading prefix but
// not a trailing suffix, so trailing text threw and silently dropped findings.
test("extractJsonObject bounds both the prefix and the suffix", () => {
  const obj = '{"runs":[{"results":[]}]}';
  // trailing text after the object (the regression this fixes)
  assert.equal(extractJsonObject(obj + "\nscan complete, 1 asset\n"), obj);
  // leading log line before the object
  assert.equal(extractJsonObject("→ loading policy\n" + obj), obj);
  // both ends, plus nested braces
  assert.equal(extractJsonObject("noise " + obj + " trailer"), obj);
  // a brace inside a JSON string must not end the object early
  const withBrace = '{"text":"} not the end {"}';
  assert.equal(extractJsonObject(withBrace + " tail"), withBrace);
  // the parsed result still feeds sarifFindings
  assert.deepEqual(sarifFindings(JSON.parse(extractJsonObject(obj + " x"))), []);
  // no object / unbalanced → null (caller returns [] → fail open)
  assert.equal(extractJsonObject("no json here"), null);
  assert.equal(extractJsonObject('{"a":1'), null);
});

// parseJsonObject: extract + parse in one step, never throwing, so both cnspec
// call sites (the mod and the shared engine) stay fail-open without a bare
// JSON.parse relying on a distant outer catch.
test("parseJsonObject returns the object or null, never throws", () => {
  assert.deepEqual(parseJsonObject('{"runs":[]} trailing log'), { runs: [] });
  assert.deepEqual(parseJsonObject("→ log\n{\"a\":1}\ndone"), { a: 1 });
  assert.equal(parseJsonObject("no json"), null);        // no object
  assert.equal(parseJsonObject('{"a":1'), null);          // unbalanced
  assert.equal(parseJsonObject("{not valid json}"), null); // balanced but invalid
});

test("cnspecScanArgs in platform mode: no bundles, no --incognito", () => {
  assert.deepEqual(cnspecScanArgs("terraform", "main.tf", ["ignored.yaml"], { platform: true }),
    ["scan", "terraform", "main.tf", "-o", "sarif"]);
  assert.deepEqual(cnspecScanArgs("docker", "Dockerfile", [], { platform: true }),
    ["scan", "docker", "file", "Dockerfile", "-o", "sarif"]);
});

test("cnspecPolicySource: bundle override → content dir → platform → public bundles", () => {
  const pub = cnspecPolicySource("docker", {});
  assert.equal(pub.kind, "bundles");
  assert.equal(pub.remote, true);
  assert.ok(pub.bundles.every((b) => b.startsWith("https://raw.githubusercontent.com/")));

  const local = cnspecPolicySource("docker", { CNSPEC_CONTENT_DIR: "/c" });
  assert.deepEqual(local, { kind: "bundles", bundles: ["/c/mondoo-dockerfile-security.mql.yaml", "/c/mondoo-dockerfile-best-practices.mql.yaml"], remote: false });

  assert.deepEqual(cnspecPolicySource("k8s", { CNSPEC_USE_PLATFORM: "1" }), { kind: "platform", bundles: [], remote: false });
  assert.equal(cnspecPolicySource("k8s", { CNSPEC_USE_PLATFORM: "true" }).kind, "platform");
  assert.equal(cnspecPolicySource("k8s", { CNSPEC_USE_PLATFORM: "0" }).kind, "bundles");
  // an explicit bundle or content dir wins over the platform switch
  assert.equal(cnspecPolicySource("k8s", { CNSPEC_USE_PLATFORM: "1", CNSPEC_POLICY_BUNDLE: "p.yaml" }).kind, "bundles");
  assert.equal(cnspecPolicySource("k8s", { CNSPEC_USE_PLATFORM: "1", CNSPEC_CONTENT_DIR: "/c" }).kind, "bundles");
  // an s3:// or https:// override is a download too
  assert.equal(cnspecPolicySource("k8s", { CNSPEC_POLICY_BUNDLE: "s3://b/p.yaml" }).remote, true);
  assert.equal(cnspecPolicySource("k8s", { CNSPEC_POLICY_BUNDLE: "./p.yaml" }).remote, false);
});

test("cnspecPolicyNotice says what goes where, and nothing when fully local", () => {
  assert.match(cnspecPolicyNotice({ kind: "bundles", remote: true }), /nothing is uploaded/);
  assert.match(cnspecPolicyNotice({ kind: "platform", remote: false }), /reports scan results/);
  assert.equal(cnspecPolicyNotice({ kind: "bundles", remote: false }), null);
  assert.equal(cnspecPolicyNotice(undefined), null);
});

test("alsoCodeScan: Terraform and Dockerfiles get xgrep too, K8s/CFN do not", () => {
  assert.equal(alsoCodeScan("terraform"), true);
  assert.equal(alsoCodeScan("docker"), true);
  assert.equal(alsoCodeScan("k8s"), false);
  assert.equal(alsoCodeScan("cloudformation"), false);
});

test("iacNeedsContent: only YAML/JSON need content to classify", () => {
  assert.equal(iacNeedsContent("k8s/deploy.yaml"), true);
  assert.equal(iacNeedsContent("C:\\infra\\stack.YML"), true);
  assert.equal(iacNeedsContent("cfn.json"), true);
  assert.equal(iacNeedsContent("main.tf.json"), false);
  assert.equal(iacNeedsContent("main.tf"), false);
  assert.equal(iacNeedsContent("Dockerfile"), false);
  assert.equal(iacNeedsContent(""), false);
});

test("combineAdvisories joins both engines; one 'File written.' lead; null when empty", () => {
  const t = combineAdvisories(["File written. cnspec policy found 1 issue(s)", null, "File written. xgrep flagged 1"]);
  assert.equal(t, "File written. cnspec policy found 1 issue(s)\n\nxgrep flagged 1");
  assert.equal(combineAdvisories([null, ""]), null);
  assert.equal(combineAdvisories(undefined), null);
});

test("advisoryText / iacAdvisoryText: pre-write wording says the file was not written", () => {
  const code = advisoryText("db.py", [{ rule: "r", title: "T", line: 1, message: "m" }], { written: false });
  assert.match(code, /^Not written: xgrep flagged 1 high-confidence security issue\(s\) in db\.py\. Fix them and write the file again:/);
  const iac = iacAdvisoryText("main.tf", "terraform", [{ rule: "r", severity: "", message: "m" }], { written: false });
  assert.match(iac, /^Not written: cnspec policy found 1 issue\(s\) in main\.tf \(terraform\)\. Fix them/);
  assert.equal(combineAdvisories([iac, code]).match(/Not written/g).length, 1);
});

test("normalizeVerdict phrases findings itself, not xgrep's 'blocked … retry' summary", () => {
  const v = normalizeVerdict({
    decision: "deny",
    summary: "xgrep guard blocked this action — sensitive data or a dangerous command:\n  - Pipe to shell (rule-a) in command at line 1\nRemove the flagged secret/PII or dangerous command and retry.",
    findings: [{ rule: "rule-a", title: "Pipe to shell", line: 1 }],
  });
  assert.equal(v.flagged, "Pipe to shell (rule-a)");
  assert.deepEqual(v.lines, ["Pipe to shell (rule-a)"]); // no padding for a missing severity
  assert.doesNotMatch(v.flagged, /blocked|retry/);
  assert.match(v.summary, /blocked this action/); // kept for the blocking adapters
});

test("normalizeVerdict: severity leads a line when present; several findings join", () => {
  const v = normalizeVerdict({ findings: [
    { rule: "r1", title: "Secret in command", severity: "high" },
    { rule: "r2", title: "r2" },
  ] });
  assert.deepEqual(v.lines, ["HIGH · Secret in command (r1)", "r2"]);
  assert.equal(v.flagged, "Secret in command (r1); r2");
  assert.equal(v.decision, "ask");
});

test("normalizeVerdict: no findings falls back to the summary's first line, then a default", () => {
  assert.equal(normalizeVerdict({ decision: "deny", summary: "Risky thing detected:\n  - detail" }).flagged, "Risky thing detected");
  assert.equal(normalizeVerdict({ decision: "deny" }).flagged, "a risky command");
});

test("validateFpReport accepts a complete report and names each missing field", () => {
  const good = { rule: "python-sql-injection", language: "python", snippet: "x = 1\n", reason: "safe" };
  assert.deepEqual(validateFpReport(good), []);
  const bad = validateFpReport({});
  assert.equal(bad.length, 4);
  assert.match(bad.join(" "), /`rule`.*`language`.*`snippet`.*`reason`/s);
  assert.match(validateFpReport({ ...good, rule: "a b" }).join(), /`rule`/);
  assert.match(validateFpReport({ ...good, language: "py thon" }).join(), /`language`/);
});

test("validateFpReport keeps the repro minimal", () => {
  const good = { rule: "r", language: "go", reason: "safe" };
  assert.match(validateFpReport({ ...good, snippet: "x\n".repeat(61) }).join(), /at most 60 lines/);
  assert.match(validateFpReport({ ...good, snippet: "x".repeat(4001) }).join(), /4000 characters/);
  assert.match(validateFpReport({ ...good, snippet: "x", reason: "y".repeat(2001) }).join(), /`reason`/);
});

test("fpReproArgs / fpReproduces: the repro command and its check", () => {
  assert.deepEqual(fpReproArgs("r1", "go"), ["scan", "--stdin", "--lang", "go", "--rule-id", "r1", "--json"]);
  assert.equal(fpReproduces({ results: [{ check_id: "r1" }] }, "r1"), true);
  assert.equal(fpReproduces({ results: [{ check_id: "r2" }] }, "r1"), false);
  assert.equal(fpReproduces(null, "r1"), false);
});

test("fpIssue: title, repro block, version, reason; optional expected; fence can't be broken", () => {
  const { title, body } = fpIssue({ rule: "r1", language: "python", snippet: "a = 1\n", reason: "safe", xgrepVersion: "0.80.0" });
  assert.equal(title, "False positive: r1 (python)");
  assert.match(body, /```python\na = 1\n```/);
  assert.match(body, /\*\*xgrep:\*\* 0\.80\.0/);
  assert.match(body, /### Why this is a false positive\n\nsafe/);
  assert.doesNotMatch(body, /### Expected/);
  assert.match(fpIssue({ rule: "r", language: "go", snippet: "x", reason: "y", expected: "no finding" }).body, /### Expected\n\nno finding/);
  const tricky = fpIssue({ rule: "r", language: "md", snippet: "```\nx\n```", reason: "y" }).body;
  assert.match(tricky, /````md\n```\nx\n```\n````/);
  assert.match(fpIssue({ rule: "r", language: "go", snippet: "x", reason: "y" }).body, /\*\*xgrep:\*\* unknown/);
});

test("fpIssueUrl prefills a new issue on the repo, labelled", () => {
  const u = new URL(fpIssueUrl({ title: "T & t", body: "b\nc" }));
  assert.equal(u.origin + u.pathname, `https://github.com/${FP_REPO}/issues/new`);
  assert.equal(u.searchParams.get("title"), "T & t");
  assert.equal(u.searchParams.get("body"), "b\nc");
  assert.equal(u.searchParams.get("labels"), FP_LABEL);
});

test("findingsNotice names Mondoo's engine, the file, and what was caught", () => {
  assert.equal(
    findingsNotice("xgrep", "/w/src/app.py", [{ rule: "python-sql-injection", title: "SQL injection", line: 15 }]),
    "Mondoo xgrep found 1 issue in app.py: SQL injection (python-sql-injection), line 15. Sent to Claude to address.",
  );
  const many = findingsNotice("cnspec", "k8s\\pod.yaml", [
    { rule: "r1", severity: "high", message: "Runs privileged" }, { rule: "r2", message: "b" },
    { rule: "r3", message: "c" }, { rule: "r4", message: "d" },
  ]);
  assert.match(many, /^Mondoo cnspec found 4 issues in pod\.yaml: HIGH Runs privileged \(r1\); b \(r2\); c \(r3\); and 1 more\./);
  assert.match(findingsNotice("xgrep", "", [{}]), /in the file: finding \(finding\)\./);
});

test("findingsToast shares findingsNotice's lead (one wording, two lengths)", () => {
  const f = [{ rule: "r", title: "T", line: 1 }, { rule: "s", title: "U", line: 2 }];
  assert.equal(findingsToast("xgrep", "/w/app.py", f), "Mondoo xgrep found 2 issues in app.py — sent to Claude");
  assert.ok(findingsNotice("xgrep", "/w/app.py", f).startsWith("Mondoo xgrep found 2 issues in app.py: "));
  // nothing found → nothing to say (never "found 0 issues … sent to Claude")
  assert.equal(findingsToast("cnspec", "main.tf", []), null);
  assert.equal(findingsNotice("cnspec", "main.tf", []), null);
  assert.equal(findingsNotice("xgrep", "a.py", undefined), null);
});

test("parseUpdateNotice reads xgrep's own notice, styled or plain", () => {
  assert.deepEqual(parseUpdateNotice("\x1b[33m⚠ A new xgrep release is available: v0.80.0 → v0.83.0\x1b[0m\n  Update with …"), { current: "0.80.0", latest: "0.83.0" });
  assert.deepEqual(parseUpdateNotice("A new xgrep release is available: 0.81.0 -> 0.83.0"), { current: "0.81.0", latest: "0.83.0" });
  assert.equal(parseUpdateNotice("xgrep 0.83.0 (commit: abc)"), null);
  assert.equal(parseUpdateNotice(undefined), null);
});

test("npmGlobalPrefix finds the npm prefix of a global install, and nothing else", () => {
  assert.equal(npmGlobalPrefix("/Users/u/.nvm/versions/node/v22/lib/node_modules/@mondoohq/xgrep/bin/xgrep.js"), "/Users/u/.nvm/versions/node/v22");
  assert.equal(npmGlobalPrefix("/opt/homebrew/lib/node_modules/@mondoohq/xgrep/index.js"), "/opt/homebrew");
  assert.equal(npmGlobalPrefix("C:\\Users\\u\\AppData\\Roaming\\npm\\node_modules\\@mondoohq\\xgrep\\bin\\xgrep.js"), "C:\\Users\\u\\AppData\\Roaming\\npm");
  assert.equal(npmGlobalPrefix("/home/u/.npm/_npx/abc/node_modules/@mondoohq/xgrep_linux_amd64/xgrep"), null); // npx cache
  assert.equal(npmGlobalPrefix("/Users/u/go/bin/xgrep"), null); // dev build
  assert.equal(npmGlobalPrefix(undefined), null);
});

test("xgrepUpdateArgv updates the install in place, or installs a global copy", () => {
  assert.deepEqual(xgrepUpdateArgv("/opt/homebrew"), ["npm", "--prefix", "/opt/homebrew", "install", "-g", "@mondoohq/xgrep@latest"]);
  assert.deepEqual(xgrepUpdateArgv(null), ["npm", "install", "-g", "@mondoohq/xgrep@latest"]);
});

test("parseVersionJSON reads version and update from xgrep version --json --check-update", () => {
  assert.deepEqual(
    parseVersionJSON(JSON.stringify({ version: "0.81.0", update: { checked: true, latest: "0.83.0", available: true } })),
    { version: "0.81.0", update: { current: "0.81.0", latest: "0.83.0" } });
  assert.deepEqual(parseVersionJSON(JSON.stringify({ version: "0.83.0", update: { checked: true, latest: "0.83.0", available: false } })),
    { version: "0.83.0", update: null });
  // not checked (opted out / lookup failed) is "unknown", not an update
  assert.deepEqual(parseVersionJSON(JSON.stringify({ version: "0.81.0", update: { checked: false, available: false } })),
    { version: "0.81.0", update: null });
  // an older xgrep printed text or an error: not the document
  assert.equal(parseVersionJSON("xgrep 0.80.0 (commit: x)"), null);
  assert.equal(parseVersionJSON('Error: unknown flag: --check-update'), null);
});
