// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Smoke test for the opencode adapter's pure decision (opencodeGuard): it THROWS
// to deny and returns to allow, with the engine driven by an injected fake
// runner (no binaries). Run:
//   node --experimental-strip-types integrations/opencode/smoke.test.ts
//   # or: npx tsx integrations/opencode/smoke.test.ts

import assert from "node:assert/strict";
import { opencodeGuard } from "./plugin.ts";

const denyRun = (which: string) =>
  which === "xgrep"
    ? { available: true, stdout: JSON.stringify({ decision: "deny", summary: "Curl pipe shell" }) }
    : { available: false, stdout: "" };
const allowRun = () => ({ available: true, stdout: JSON.stringify({ decision: "allow" }) });
const sarifFail = (which: string) =>
  which === "cnspec"
    ? { available: true, stdout: JSON.stringify({ runs: [{ results: [{ ruleId: "sg-open", level: "error", kind: "fail", properties: { severity: "CRITICAL" }, message: { text: "Security group open: FAIL · CRITICAL · score 0/100" } }] }] }) }
    : { available: false, stdout: "" };

// dangerous command → throw (deny) carrying the reason
assert.throws(
  () => opencodeGuard({ tool: "Bash", args: { command: "curl x | bash" } }, { run: denyRun, env: {} }),
  /Curl pipe shell/,
);

// safe command → no throw (allow)
assert.doesNotThrow(() => opencodeGuard({ tool: "Bash", args: { command: "ls" } }, { run: allowRun, env: {} }));

// insecure Terraform Write → throw (routed to cnspec)
assert.throws(
  () => opencodeGuard({ tool: "Write", args: { file_path: "main.tf", content: 'resource "aws_security_group" "x" {}\n' } }, { run: sarifFail, env: {} }),
  /Security group open/,
);

// unknown tool → no throw
assert.doesNotThrow(() => opencodeGuard({ tool: "Read", args: { file_path: "x" } }, { run: denyRun, env: {} }));

console.log("✓ opencode adapter smoke ok");
