// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for the external hook's pure seams: event parsing (the permissive
// union of field names Codex/Vibe send) and per-agent decision formatting. The
// routing + scanner I/O is exercised end-to-end by pipeline-scenario.mjs against
// the real binaries. Run with `node --test integrations/shared/*.test.mjs`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { parseEvent, formatDecision } from "./hook.mjs";

test("parseEvent reads the Claude/Codex shape (tool_name + tool_input)", () => {
  const ev = parseEvent(JSON.stringify({
    tool_name: "Bash", tool_input: { command: "rm -rf /" },
  }));
  assert.equal(ev.tool, "Bash");
  assert.equal(ev.command, "rm -rf /");
});

test("parseEvent reads a Write event with proposed content", () => {
  const ev = parseEvent(JSON.stringify({
    tool_name: "Write", tool_input: { file_path: "app.py", content: "x = 1\n" },
  }));
  assert.equal(ev.tool, "Write");
  assert.equal(ev.filePath, "app.py");
  assert.equal(ev.content, "x = 1\n");
});

test("parseEvent tolerates alternate field names (tool / input / flat)", () => {
  assert.equal(parseEvent(JSON.stringify({ tool: "shell", command: "ls" })).command, "ls");
  assert.equal(parseEvent(JSON.stringify({ toolName: "Write", input: { file_path: "a.go" } })).filePath, "a.go");
  assert.equal(parseEvent(JSON.stringify({ tool_name: "Write", file_path: "b.ts", content: "y" })).content, "y");
});

test("parseEvent leaves content undefined when absent (so Write review is skipped)", () => {
  const ev = parseEvent(JSON.stringify({ tool_name: "Write", tool_input: { file_path: "a.py" } }));
  assert.equal(ev.content, undefined);
});

test("parseEvent is total on garbage", () => {
  assert.deepEqual(parseEvent("not json"), {});
  assert.deepEqual(parseEvent(""), {});
  assert.equal(parseEvent("{}").tool, "");
});

test("formatDecision: allow is silence for every agent", () => {
  assert.equal(formatDecision("codex", "allow", "x"), null);
  assert.equal(formatDecision("mistral", "allow", "x"), null);
});

test("formatDecision: Codex maps deny→block and keeps ask", () => {
  assert.deepEqual(JSON.parse(formatDecision("codex", "deny", "bad command")),
    { decision: "block", reason: "bad command" });
  assert.deepEqual(JSON.parse(formatDecision("codex", "ask", "please confirm")),
    { decision: "ask", reason: "please confirm" });
});

test("formatDecision: Vibe denies (no ask channel — ask collapses to deny)", () => {
  assert.deepEqual(JSON.parse(formatDecision("mistral", "deny", "secret leak")),
    { decision: "deny", reason: "secret leak" });
  assert.deepEqual(JSON.parse(formatDecision("mistral", "ask", "risky")),
    { decision: "deny", reason: "risky" });
});
