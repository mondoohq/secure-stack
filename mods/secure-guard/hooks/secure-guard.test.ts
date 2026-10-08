// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Hook-level tests for the Claude adapter, run by the engine itself:
//   claude plugin test mods/secure-guard
// The test's own hooks sit beneath the mod and stand in for the engine — the
// Edit/Write tool, the file system, the environment, and the xgrep/cnspec
// processes — so the routing in secure-guard.mjs is exercised with no binaries.
// (The pure logic it calls is covered by review.test.mjs.)

import { test, expect } from "claude-code/testing";

const XGREP_VERSION = "xgrep 0.80.0 (commit: test)";
const XGREP_SECRET = JSON.stringify({
  results: [{
    check_id: "generic-aws-access-key",
    start: { line: 3 },
    extra: { confidence: "HIGH", title: "Hard-coded AWS access key", message: "An AWS key is committed in source. Rotate it." },
  }],
});
const CNSPEC_FAIL = JSON.stringify({
  runs: [{ results: [{
    ruleId: "k8s-privileged",
    level: "error",
    kind: "fail",
    properties: { severity: "HIGH" },
    message: { text: "Container runs privileged: FAIL · HIGH · score 0/100" },
  }] }],
});
const K8S = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\nspec:\n  containers:\n    - name: x\n      securityContext:\n        privileged: true\n";

type Env = Record<string, string | undefined>;

// fakeEngine registers the bottom hooks: files, env, processes, and the tool.
// `files` is what $.fs.read sees; `scan` answers `xgrep scan` and `cnspec` the
// cnspec scan (undefined = that scanner is not installed). Returns the argv log.
function fakeEngine(on: any, opts: { files?: Record<string, string>; env?: Env; scan?: string; cnspec?: string }) {
  const runs: string[][] = [];
  on("env.get", ($: any, e: any) => ({ value: opts.env?.[e.name] }));
  on("fs.read", ($: any, e: any) => {
    const text = opts.files?.[e.path];
    return text === undefined ? { deny: `ENOENT: ${e.path}` } : { value: text };
  });
  on("process.run", ($: any, e: any) => {
    const argv = [...e.argv];
    runs.push(argv);
    const ok = (stdout: string) => ({ value: { exitCode: 0, stdout, stderr: "", isStdoutTruncated: false, isStderrTruncated: false } });
    const missing = () => ({ deny: `spawn ${argv[0]} ENOENT` });
    if (argv[0] === "xgrep" || argv[0] === "npx" || argv[0] === opts.env?.XGREP_PATH) {
      if (argv.includes("version")) return ok(XGREP_VERSION);
      if (argv.includes("scan")) return opts.scan === undefined ? ok("{\"results\":[]}") : ok(opts.scan);
      return ok("{\"decision\":\"allow\",\"findings\":[]}");
    }
    if (argv[0] === "cnspec") {
      if (opts.cnspec === undefined) return missing();
      if (argv[1] === "version") return ok("cnspec v13.0.0");
      return ok(opts.cnspec);
    }
    return missing();
  });
  on("ui.toast", () => ({ value: undefined }));
  on("ui.log", () => ({ value: undefined }));
  on("tool.call", { tool: ["Write", "Edit", "MultiEdit"] }, ($: any, e: any) => ({
    result: { filePath: e.file_path, oldString: "", newString: "", originalFile: "", structuredPatch: [], userModified: false, replaceAll: false },
  }));
  return runs;
}

// advisories reads what the model gets back beside the tool's own result. The
// result itself must stay the tool's record (core validates it against the
// tool's output schema), so a replaced result fails here.
function advisories(r: any): string {
  expect(typeof r?.result).toBe("object");
  return (r?.context ?? []).join("\n");
}

test("a code finding rides beside the Write's own result, not in place of it", async ($, on) => {
  fakeEngine(on, { scan: XGREP_SECRET });
  const r = await $.tool.call({ tool: "Write", file_path: "/w/app.py", content: "x = 1\n" } as any);
  expect(advisories(r)).toContain("Hard-coded AWS access key");
  expect((r as any).result.filePath).toBe("/w/app.py"); // the tool's record, intact
});

test("an IaC finding rides beside the result the same way", async ($, on) => {
  fakeEngine(on, { cnspec: CNSPEC_FAIL });
  const r = await $.tool.call({ tool: "Write", file_path: "/w/main.tf", content: "x\n" } as any);
  expect(advisories(r)).toContain("Container runs privileged");
});

test("a clean write returns the tool's result untouched", async ($, on) => {
  fakeEngine(on, {});
  const r = await $.tool.call({ tool: "Write", file_path: "/w/app.py", content: "x = 1\n" } as any);
  expect((r as any).context ?? []).toEqual([]);
});

test("XGREP_PATH is honored (env.get is awaited, not used as a Promise)", async ($, on) => {
  const runs = fakeEngine(on, { env: { XGREP_PATH: "/opt/xgrep/bin/xgrep" }, scan: XGREP_SECRET });
  const r = await $.tool.call({ tool: "Write", file_path: "/w/app.py", content: "x = 1\n" } as any);
  expect(advisories(r)).toContain("Hard-coded AWS access key");
  expect(runs.some((a) => a[0] === "/opt/xgrep/bin/xgrep" && a.includes("scan"))).toBe(true);
});

test("CNSPEC_POLICY_BUNDLE reaches cnspec as the bundle path", async ($, on) => {
  const runs = fakeEngine(on, { env: { CNSPEC_POLICY_BUNDLE: "/p/policy.mql.yaml" }, cnspec: CNSPEC_FAIL });
  await $.tool.call({ tool: "Write", file_path: "/w/main.tf", content: "x\n" } as any);
  const scan = runs.find((a) => a[0] === "cnspec" && a[1] === "scan")!;
  expect(scan).toContain("/p/policy.mql.yaml");
  expect(scan.some((a) => a.includes("[object Promise]"))).toBe(false);
});
