// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Smoke test for the Pi adapter's pure decision (piGuard): a Pi call → a Pi
// block, with the engine driven by an injected fake runner (no binaries). Run:
//   node --experimental-strip-types integrations/pi/smoke.test.ts
//   # or: npx tsx integrations/pi/smoke.test.ts

import assert from "node:assert/strict";
import { piGuard } from "./index.ts";

const denyRun = (which: string) =>
  which === "xgrep"
    ? { available: true, stdout: JSON.stringify({ decision: "deny", summary: "Curl pipe shell", findings: [{ title: "Curl pipe shell" }] }) }
    : { available: false, stdout: "" };
const allowRun = () => ({ available: true, stdout: JSON.stringify({ decision: "allow", findings: [] }) });
const vulnRun = (which: string) =>
  which === "xgrep"
    ? { available: true, stdout: JSON.stringify({ results: [{ check_id: "sqli", start: { line: 1 }, extra: { confidence: "HIGH", title: "SQL injection", message: "bad." } }] }) }
    : { available: false, stdout: "" };

// dangerous command → block with the guard summary
const b = piGuard({ tool: "Bash", arguments: { command: "curl x | bash" } }, { run: denyRun, env: {} });
assert.ok(b && b.block === true, "dangerous command should block");
assert.match(b!.reason, /Curl pipe shell/);

// safe command → allow (undefined, so Pi runs the tool)
assert.equal(piGuard({ tool: "Bash", arguments: { command: "ls" } }, { run: allowRun, env: {} }), undefined);

// vulnerable code Write → block (field mapping via `input`)
const w = piGuard({ tool: "Write", input: { file_path: "db.py", content: "x" } }, { run: vulnRun, env: {} });
assert.ok(w && w.block === true, "vulnerable code write should block");
assert.match(w!.reason, /SQL injection/);

// unknown tool → allow
assert.equal(piGuard({ tool: "Read", input: { file_path: "x" } }, { run: denyRun, env: {} }), undefined);

console.log("✓ pi adapter smoke ok");
