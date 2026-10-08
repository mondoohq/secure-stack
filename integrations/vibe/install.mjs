#!/usr/bin/env node
// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Install the secure-guard pre-tool hook for Mistral Vibe into a project.
//
//   node integrations/vibe/install.mjs [target-dir]   (default: cwd)
//
// It writes/merges `<target>/.vibe/hooks.toml` so Vibe runs the hub's shared
// `hook.mjs` (as a Vibe adapter) before every tool call: a dangerous shell
// command or a vulnerable/secret-leaking Write is denied; everything else runs.
// Re-running is idempotent — it won't add a second block for the same command.

import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const HOOK = resolve(HERE, "..", "shared", "hook.mjs");
const AGENT = "mistral";
const MARKER = "# secure-guard (Mondoo) — managed hook; remove this block to uninstall";

// Vibe spawns `command` with the tool event JSON on stdin and reads a decision
// ({"decision":"allow"|"deny","reason"}) back; no output = allow. We write the
// command as an argv array so a path with spaces survives.
function block() {
  const argv = JSON.stringify(["node", HOOK, "--agent", AGENT]);
  return `${MARKER}\n[[pre_tool]]\ncommand = ${argv}\n`;
}

function main() {
  const target = resolve(process.argv[2] || process.cwd());
  const dir = join(target, ".vibe");
  const file = join(dir, "hooks.toml");

  let existing = "";
  if (existsSync(file)) existing = readFileSync(file, "utf8");

  if (existing.includes(HOOK) && existing.includes(AGENT)) {
    console.log(`secure-guard: already installed in ${file}`);
    return;
  }

  const sep = existing && !existing.endsWith("\n") ? "\n" : "";
  const out = existing + sep + (existing ? "\n" : "") + block();

  mkdirSync(dir, { recursive: true });
  writeFileSync(file, out);
  console.log(`secure-guard: installed Vibe pre-tool hook → ${file}`);
  console.log(`  runs: node ${HOOK} --agent ${AGENT}`);
  console.log("  xgrep (shell+code) must be on PATH or via XGREP_PATH; cnspec (IaC) optional.");
}

main();
