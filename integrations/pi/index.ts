// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// secure-guard for Pi (github.com/earendil-works/pi) — an in-process TS
// extension. Pi has no external-command hook, so gating is a module loaded into
// the agent that returns a decision on the `tool_call` hook. All routing and
// scanner I/O is the shared engine; this file only maps Pi's event in and Pi's
// decision out.
//
//   Bash  → `xgrep guard --command` (secrets/PII + dangerous command)
//   Write → `xgrep scan` code / `cnspec scan` IaC (OWASP Top 10 / policy)
//
// Pre-tool, fail-open. Requires node + xgrep (≥ 0.84, PATH or XGREP_PATH); cnspec
// optional for the IaC leg.
//
// NOTE: Pi is fast-moving — confirm the hook name (`tool_call`), the call fields,
// and the block-return shape against your installed version
// (packages/coding-agent/docs/extensions.md). The decision logic below is
// version-independent; only the thin wiring in `register()` touches Pi's API.

// @ts-ignore — engine is plain ESM JS; tsx resolves it, types are structural.
import { evaluate, toEvent } from "../shared/engine.mjs";

export interface PiCall {
  tool?: string;
  name?: string;
  arguments?: Record<string, unknown>;
  input?: Record<string, unknown>;
  params?: Record<string, unknown>;
}
export type PiBlock = { block: true; reason: string } | undefined;

// piGuard is the pure decision: a Pi call → a Pi block (or undefined = allow).
// `opts` forwards { run, env } to the engine so it is testable without binaries.
export function piGuard(call: PiCall, opts: Record<string, unknown> = {}): PiBlock {
  const ev = toEvent(call?.tool ?? call?.name, call?.arguments ?? call?.input ?? call?.params);
  const { decision, reason } = evaluate(ev, opts);
  // "ask" blocks too until a prompt is wired (see register()).
  return decision === "allow" ? undefined : { block: true, reason: reason as string };
}

// The Pi extension entry point. Pi loads the default export and invokes the
// `tool_call` hook before each tool runs; returning { block, reason } stops it.
// To prompt instead of hard-blocking, swap the block for `ctx.ui.confirm(reason)`.
export default function register() {
  return {
    name: "secure-guard",
    hooks: {
      tool_call: (call: PiCall /*, ctx */) => piGuard(call),
    },
  };
}
