#!/usr/bin/env node
// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Install the secure-guard pre-tool hook for OpenAI Codex into a project.
//
//   node integrations/codex/install.mjs [target-dir]   (default: cwd)
//
// It writes/merges `<target>/.codex/hooks.json` so Codex runs the hub's shared
// `hook.mjs` (as a Codex adapter) before every tool call: a dangerous shell
// command or a vulnerable/secret-leaking Write is blocked; everything else runs.
// Re-running is idempotent — it de-dupes on the hook command.

import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const HOOK = resolve(HERE, "..", "shared", "hook.mjs"); // the shared command
const AGENT = "codex";

// The Codex pre-tool hook entry. Codex spawns `command` with the tool event as
// JSON on stdin and reads a decision ({"decision":"block"|"ask","reason"}) back;
// no output = allow. See integrations/codex/README.md.
function hookEntry() {
  return { event: "PreToolUse", command: ["node", HOOK, "--agent", AGENT] };
}

function sameHook(e) {
  return Array.isArray(e?.command) && e.command.includes(HOOK) && e.command.includes(AGENT);
}

function main() {
  const target = resolve(process.argv[2] || process.cwd());
  const dir = join(target, ".codex");
  const file = join(dir, "hooks.json");

  let doc = { hooks: [] };
  if (existsSync(file)) {
    try { doc = JSON.parse(readFileSync(file, "utf8")) || {}; } catch { doc = {}; }
  }
  if (!Array.isArray(doc.hooks)) doc.hooks = [];

  if (doc.hooks.some(sameHook)) {
    console.log(`secure-guard: already installed in ${file}`);
    return;
  }
  doc.hooks.push(hookEntry());

  mkdirSync(dir, { recursive: true });
  writeFileSync(file, JSON.stringify(doc, null, 2) + "\n");
  console.log(`secure-guard: installed Codex pre-tool hook → ${file}`);
  console.log(`  runs: node ${HOOK} --agent ${AGENT}`);
  console.log("  xgrep (shell+code) must be on PATH or via XGREP_PATH; cnspec (IaC) optional.");
}

main();
