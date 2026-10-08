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

test("meetsMin gates on the 0.78.0 floor (guard --command)", () => {
  assert.equal(meetsMin("0.80.0"), true);
  assert.equal(meetsMin("0.78.0"), true); // the floor itself
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
