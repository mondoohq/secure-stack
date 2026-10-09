// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// secure-guard for opencode (github.com/anomalyco/opencode) — an in-process
// TS plugin. opencode has no external-command gate and no native "ask": a plugin
// hooks `tool.execute.before` and **throws** to deny. All routing and scanner
// I/O is the shared engine; this file only maps opencode's event in and turns a
// deny into a throw.
//
//   Bash  → `xgrep guard --command` (secrets/PII + dangerous command)
//   Write → `xgrep scan` code / `cnspec scan` IaC (OWASP Top 10 / policy)
//
// Pre-tool, fail-open (a missing/old/erroring scanner never throws). Requires
// node + xgrep (≥ 0.84, PATH or XGREP_PATH); cnspec optional for the IaC leg.
//
// NOTE: opencode moved sst→anomalyco and its v2 docs are in flux — confirm the
// hook name (`tool.execute.before`) and where the tool args live against your
// installed version (opencode.ai/docs/plugins). The decision logic is
// version-independent; only the thin wiring touches opencode's API.

// @ts-ignore — engine is plain ESM JS; tsx resolves it, types are structural.
import { evaluate, toEvent } from "../shared/engine.mjs";

export interface OpencodeToolEvent {
  tool?: string;
  args?: Record<string, unknown>;
  input?: Record<string, unknown>;
}

// opencodeGuard is the pure decision: inspect a tool-execute event and THROW
// (deny) on a finding; return (allow) otherwise. `opts` forwards { run, env } to
// the engine so it is testable without binaries.
export function opencodeGuard(evt: OpencodeToolEvent, opts: Record<string, unknown> = {}): void {
  const ev = toEvent(evt?.tool, evt?.args ?? evt?.input);
  const { decision, reason } = evaluate(ev, opts);
  // opencode has no native "ask": an "ask" verdict denies, like "deny".
  if (decision !== "allow") throw new Error(reason as string);
}

// The opencode plugin entry point: an async factory returning the hooks object.
// `tool.execute.before` receives the tool identity and the (mutable) input args;
// throwing cancels the call with the message as the reason.
export const SecureGuardPlugin = async (_ctx: Record<string, unknown> = {}) => ({
  "tool.execute.before": async (
    input: { tool?: string },
    output: { args?: Record<string, unknown> },
  ) => {
    opencodeGuard({ tool: input?.tool, args: output?.args });
  },
});

export default SecureGuardPlugin;
