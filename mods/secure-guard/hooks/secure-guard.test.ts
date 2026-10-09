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

test("Edit on a K8s manifest reads the file, classifies it, and runs cnspec", async ($, on) => {
  const runs = fakeEngine(on, { files: { "/w/deploy.yaml": K8S }, cnspec: CNSPEC_FAIL });
  const r = await $.tool.call({ tool: "Edit", file_path: "/w/deploy.yaml", old_string: "a", new_string: "b" } as any);
  expect(advisories(r)).toContain("Container runs privileged");
  expect(runs.some((a) => a[0] === "cnspec" && a.includes("k8s"))).toBe(true);
});

test("Edit on plain YAML that is not IaC stays quiet", async ($, on) => {
  const runs = fakeEngine(on, { files: { "/w/config.yaml": "name: x\n" }, cnspec: CNSPEC_FAIL });
  const r = await $.tool.call({ tool: "Edit", file_path: "/w/config.yaml", old_string: "a", new_string: "b" } as any);
  expect(advisories(r)).toBe("");
  expect(runs.some((a) => a[0] === "cnspec" && a[1] === "scan")).toBe(false);
});

test("Terraform gets both engines: cnspec policy and the xgrep secret scan", async ($, on) => {
  const runs = fakeEngine(on, { scan: XGREP_SECRET, cnspec: CNSPEC_FAIL });
  const r = await $.tool.call({ tool: "Write", file_path: "/w/main.tf", content: "resource \"x\" \"y\" {}\n" } as any);
  const text = advisories(r);
  expect(text).toContain("Container runs privileged"); // cnspec leg
  expect(text).toContain("Hard-coded AWS access key"); // xgrep leg
  expect(runs.some((a) => a.includes("scan") && a.includes("/w/main.tf") && a[0] !== "cnspec")).toBe(true);
});

test("Dockerfile secret is still reported when cnspec is not installed", async ($, on) => {
  fakeEngine(on, { scan: XGREP_SECRET }); // no cnspec
  const r = await $.tool.call({ tool: "Write", file_path: "/w/Dockerfile", content: "FROM alpine\n" } as any);
  expect(advisories(r)).toContain("Hard-coded AWS access key");
});

test("CNSPEC_USE_PLATFORM runs the space's policies: no bundles, no --incognito", async ($, on) => {
  const runs = fakeEngine(on, { env: { CNSPEC_USE_PLATFORM: "1" }, cnspec: CNSPEC_FAIL });
  await $.tool.call({ tool: "Write", file_path: "/w/main.tf", content: "x\n" } as any);
  const scan = runs.find((a) => a[0] === "cnspec" && a[1] === "scan")!;
  expect(scan.includes("--incognito")).toBe(false);
  expect(scan.includes("-f")).toBe(false);
});

test("by default cnspec runs incognito against the public bundles", async ($, on) => {
  const runs = fakeEngine(on, { cnspec: CNSPEC_FAIL });
  await $.tool.call({ tool: "Write", file_path: "/w/main.tf", content: "x\n" } as any);
  const scan = runs.find((a) => a[0] === "cnspec" && a[1] === "scan")!;
  expect(scan.includes("--incognito")).toBe(true);
  expect(scan.some((a) => a.startsWith("https://raw.githubusercontent.com/mondoohq/cnspec/"))).toBe(true);
});

// ─── False-positive reports ──────────────────────────────────────────────────

const FP_TOOL = "mcp__secure-guard__report_false_positive";
const FP_INPUT = {
  rule: "python-sql-injection",
  language: "python",
  snippet: "def q(conn):\n    return conn.execute(\"SELECT 1 WHERE id = \" + str(int(\"5\")))\n",
  reason: "The concatenated value is an int literal, never user input.",
};
const REPRO_HIT = JSON.stringify({ version: "0.80.0", results: [{ check_id: "python-sql-injection", start: { line: 2 }, extra: {} }] });
const REPRO_MISS = JSON.stringify({ version: "0.80.0", results: [] });

// fakeReporting adds what the report flow needs beneath the mod: the xgrep
// repro scan (stdin), `gh`, the pane, the clock and the hold loop's sleeps.
// `opened` resolves when the review pane opens; `ghRuns` logs gh calls.
function fakeReporting(on: any, opts: { repro?: string; reproErr?: string; gh?: "ok" | "nolabel" | "missing" }) {
  const runs: string[][] = [];
  const ghRuns: { argv: string[]; stdin: string }[] = [];
  let open: () => void = () => {};
  const opened = new Promise<void>((r) => { open = r; });
  const ok = (stdout: string, stderr = "", exitCode = 0) => ({ value: { exitCode, stdout, stderr, isStdoutTruncated: false, isStderrTruncated: false } });
  on("env.get", () => ({ value: undefined }));
  on("ui.toast", () => ({ value: undefined }));
  on("ui.log", () => ({ value: undefined }));
  on("ui.invalidate", () => ({ value: undefined }));
  on("ui.close", () => ({ value: undefined }));
  on("ui.open", () => { open(); return { value: { isPlaced: true } }; });
  on("clock.now", () => ({ value: Date.now() }));
  on("process.run", ($: any, e: any) => {
    const argv = [...e.argv];
    runs.push(argv);
    // The hold loop sleeps between checks; a real (short) delay keeps it from
    // spinning while the test presses a button.
    if (argv[0] === "sleep") return new Promise((r) => setTimeout(() => r(ok("")), 20));
    if (argv[0] === "xgrep") {
      if (argv.includes("version")) return ok(XGREP_VERSION);
      if (argv.includes("--stdin")) return opts.reproErr ? ok("", opts.reproErr, 2) : ok(opts.repro ?? REPRO_HIT);
      return ok("{\"results\":[]}");
    }
    if (argv[0] === "gh") {
      ghRuns.push({ argv, stdin: e.init?.stdin ?? "" });
      if (opts.gh === "missing") return { deny: "spawn gh ENOENT" };
      if (opts.gh === "nolabel" && argv.includes("--label")) return ok("", "could not add label: 'false-positive' not found", 1);
      return ok("https://github.com/mondoohq/secure-stack/issues/123\n");
    }
    return { deny: `spawn ${argv[0]} ENOENT` };
  });
  return { runs, ghRuns, opened };
}

// review mounts the review pane once it opens and returns it, so a test can
// read what the user sees and press a button.
async function review($: any, opened: Promise<void>) {
  await opened;
  return $.ui.mount({ plugin: "secure-guard", surface: "terminal", component: "Pane", requestId: "secure-guard", props: {} as any });
}

test("report: invalid input is answered with what to fix — no scan, no pane", async ($, on) => {
  const { runs } = fakeReporting(on, {});
  const r: any = await $.tool.call({ tool: FP_TOOL, rule: "", language: "python", snippet: "", reason: "" } as any);
  expect(String(r.result)).toContain("Not filed");
  expect(String(r.result)).toContain("`rule`");
  expect(runs.some((a) => a.includes("--stdin"))).toBe(false);
});

test("report: a snippet that doesn't trigger the rule is not filed", async ($, on) => {
  const { ghRuns } = fakeReporting(on, { repro: REPRO_MISS });
  const r: any = await $.tool.call({ tool: FP_TOOL, ...FP_INPUT } as any);
  expect(String(r.result)).toContain("does not trigger python-sql-injection");
  expect(ghRuns.length).toBe(0);
});

test("report: an unknown rule id is reported back from xgrep", async ($, on) => {
  fakeReporting(on, { reproErr: "error: unknown --rule-id value \"nope\"" });
  const r: any = await $.tool.call({ tool: FP_TOOL, ...FP_INPUT, rule: "nope" } as any);
  expect(String(r.result)).toContain("unknown --rule-id");
});

test("report: the snippet goes to xgrep on stdin with the rule filter", async ($, on) => {
  const { runs, opened } = fakeReporting(on, {});
  const call = $.tool.call({ tool: FP_TOOL, ...FP_INPUT } as any);
  const pane = await review($, opened);
  await pane.press({ key: "cancel" });
  await call;
  const scan = runs.find((a) => a.includes("--stdin"))!;
  expect(scan).toEqual(["xgrep", "scan", "--stdin", "--lang", "python", "--rule-id", "python-sql-injection", "--json"]);
});

test("report: the user sees the exact issue, and Cancel files nothing", async ($, on) => {
  const { ghRuns, opened } = fakeReporting(on, {});
  const call = $.tool.call({ tool: FP_TOOL, ...FP_INPUT } as any);
  const pane = await review($, opened);
  expect(await pane.find({ text: /False positive: python-sql-injection \(python\)/ })).toBeTruthy();
  expect(await pane.find({ text: /\(public\)/ })).toBeTruthy();
  await pane.press({ key: "cancel" });
  const r: any = await call;
  expect(String(r.result)).toContain("Not filed: the user pressed Cancel");
  expect(ghRuns.length).toBe(0);
});

test("report: File issue files it with gh, body on stdin, labelled", async ($, on) => {
  const { ghRuns, opened } = fakeReporting(on, { gh: "ok" });
  const call = $.tool.call({ tool: FP_TOOL, ...FP_INPUT } as any);
  await (await review($, opened)).press({ key: "file" });
  const r: any = await call;
  expect(String(r.result)).toContain("Filed https://github.com/mondoohq/secure-stack/issues/123");
  expect(ghRuns.length).toBe(1);
  expect(ghRuns[0].argv).toContain("--label");
  expect(ghRuns[0].argv.slice(0, 5)).toEqual(["gh", "issue", "create", "--repo", "mondoohq/secure-stack"]);
  // the body is the reviewed issue: repro, rule, xgrep version, and the reason
  expect(ghRuns[0].stdin).toContain("str(int(");
  expect(ghRuns[0].stdin).toContain("**xgrep:** 0.80.0");
  expect(ghRuns[0].stdin).toContain("int literal, never user input");
});

test("report: a repo without the label still gets the issue", async ($, on) => {
  const { ghRuns, opened } = fakeReporting(on, { gh: "nolabel" });
  const call = $.tool.call({ tool: FP_TOOL, ...FP_INPUT } as any);
  await (await review($, opened)).press({ key: "file" });
  const r: any = await call;
  expect(String(r.result)).toContain("Filed https://github.com/");
  expect(ghRuns.length).toBe(2);
  expect(ghRuns[1].argv.includes("--label")).toBe(false);
});

test("report: without gh, the user gets a prefilled link instead", async ($, on) => {
  const { opened } = fakeReporting(on, { gh: "missing" });
  const call = $.tool.call({ tool: FP_TOOL, ...FP_INPUT } as any);
  await (await review($, opened)).press({ key: "file" });
  const r: any = await call;
  expect(String(r.result)).toContain("Not filed automatically");
  expect(String(r.result)).toContain("https://github.com/mondoohq/secure-stack/issues/new?title=False+positive");
});

test("code advisories point the agent at the false-positive report", async ($, on) => {
  fakeEngine(on, { scan: XGREP_SECRET });
  const r = await $.tool.call({ tool: "Write", file_path: "/w/app.py", content: "x = 1\n" } as any);
  expect(advisories(r)).toContain("report_false_positive");
});
