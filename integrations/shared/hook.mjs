#!/usr/bin/env node
// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// secure-guard external hook — the shared pre-tool command for agents that
// gate a tool call by spawning a program with the event JSON on stdin and
// reading a decision back (OpenAI Codex, Mistral Vibe).
//
// Usage: node hook.mjs --agent codex|mistral   (event JSON on stdin)
//
// Routing + scanner I/O live in engine.mjs (shared with the Pi/opencode
// extensions); this file only does the stdin/stdout translation for the two
// external-hook agents. It fires BEFORE the tool, so a Write is scanned on its
// proposed content and vulnerable code can be blocked. (Edit/MultiEdit deliver
// only a fragment pre-tool, so code review there is left to the shell + Write
// legs.) Fail-open: a missing/old/erroring scanner or any throw → allow.

import { evaluate } from "./engine.mjs";

// ─── decision → the agent's wire format ──────────────────────────────────────
// formatDecision is pure: it maps a neutral decision to the one line each agent
// reads off stdout, or null for "allow" (silence = let the tool run).
//   Codex  — {"decision":"block"|"ask","reason"} (allow = no output)
//   Vibe   — {"decision":"deny","reason"}        (allow = no output; Vibe has no "ask")
export function formatDecision(agent, decision, reason) {
  if (decision === "allow") return null;
  const wire = agent === "codex"
    ? { decision: decision === "ask" ? "ask" : "block", reason }
    : { decision: "deny", reason };
  return JSON.stringify(wire);
}

// ─── event parsing ───────────────────────────────────────────────────────────
// Permissive union over the field names Codex/Vibe send → the engine's neutral
// event shape { tool, command, filePath, content }.
export function parseEvent(raw) {
  let e = {};
  try { e = JSON.parse(raw); } catch { return {}; }
  const tool = e.tool_name ?? e.tool ?? e.toolName ?? "";
  const input = e.tool_input ?? e.input ?? e;
  return {
    tool,
    command: input?.command ?? e.command ?? "",
    filePath: input?.file_path ?? e.file_path ?? "",
    content: typeof input?.content === "string" ? input.content : (typeof e.content === "string" ? e.content : undefined),
  };
}

// ─── main ────────────────────────────────────────────────────────────────────
async function main() {
  const agent = (process.argv[process.argv.indexOf("--agent") + 1] || "codex").toLowerCase();
  const raw = await new Promise((res) => {
    let b = ""; process.stdin.setEncoding("utf8");
    process.stdin.on("data", (d) => (b += d)); process.stdin.on("end", () => res(b));
  });
  const { decision, reason } = evaluate(parseEvent(raw));
  const line = formatDecision(agent, decision, reason);
  if (line != null) process.stdout.write(line + "\n");
}

// Run as a command; stay importable for tests (parseEvent/formatDecision).
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(() => { /* fail open */ });
}
