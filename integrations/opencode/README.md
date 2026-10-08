# secure-guard for opencode

Runs Mondoo's scanners as an in-process **`tool.execute.before`** guard in
[opencode](https://opencode.ai) (`github.com/anomalyco/opencode`). opencode has no
external-command gate, so the guard ships as a TS plugin that **throws** to deny a
tool call.

- **Shell** — the proposed command goes to `xgrep guard --command`; a secret/PII
  leak or a dangerous command is **denied** (the plugin throws).
- **Write (code)** — the proposed content is scanned with `xgrep scan` (OWASP Top
  10 / SAST / secrets); a high-confidence finding **denies** the write.
- **Write (IaC)** — Terraform / Dockerfile / Kubernetes / CloudFormation content is
  policy-checked with `cnspec`; a failed policy **denies** the write.

Everything else runs. opencode has **no native "ask"** — the guard is binary
allow/deny. **Fail-open**: a missing/old/erroring scanner never throws.

## Install

Drop `plugin.ts` into the project's `.opencode/plugins/` (see
opencode.ai/docs/plugins). opencode loads the default export and calls the
`tool.execute.before` hook before each tool; the plugin throws to cancel the call
with the finding as the reason. The guard logic is version-independent; only the
thin wiring touches opencode's API — **confirm the hook name and where the tool
args live against your installed version** (the repo moved sst→anomalyco and its
v2 docs are in flux).

## Decision contract

`opencodeGuard(evt)` **throws** `Error(reason)` to deny the tool call, or returns
to allow it. opencode surfaces the thrown message to the agent.

## Requirements

- **node** on `PATH`.
- **xgrep** with `guard --command` (≥ 0.78) on `PATH` or via `XGREP_PATH` —
  [xgrep.ai](https://xgrep.ai) / [docs](https://mondoo.com/docs/xgrep) / `@mondoohq/xgrep` on npm.
- **cnspec** on `PATH` or via `CNSPEC_PATH` for the IaC leg (optional).

## Testing

`node --experimental-strip-types integrations/opencode/smoke.test.ts` (or `npx tsx
…`) drives `opencodeGuard` with a fake runner — throws on deny (shell + IaC),
returns on allow — with no binaries. The real binaries are covered by the shared
engine's scenario.
