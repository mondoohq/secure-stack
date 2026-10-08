# secure-guard for Pi

Runs Mondoo's scanners as an in-process **`tool_call`** guard in
[Pi](https://pi.dev) (`github.com/earendil-works/pi). Pi has no external-command
hook, so the guard ships as a TS extension loaded into the agent.

- **Shell** — the proposed command goes to `xgrep guard --command`; a secret/PII
  leak or a dangerous command is **blocked**.
- **Write (code)** — the proposed content is scanned with `xgrep scan` (OWASP Top
  10 / SAST / secrets); a high-confidence finding **blocks** the write.
- **Write (IaC)** — Terraform / Dockerfile / Kubernetes / CloudFormation content is
  policy-checked with `cnspec`; a failed policy **blocks** the write.

Everything else runs. **Fail-open**: a missing/old/erroring scanner allows the call.

## Install

Pi loads this directory as an extension (see Pi's
`packages/coding-agent/docs/extensions.md`). The default export registers a
`tool_call` hook that calls the shared engine. The guard logic is
version-independent; only the thin wiring in `index.ts`'s `register()` touches
Pi's API — **confirm the hook name and the block-return shape against your
installed Pi version**, as the API is still moving (native allow/deny/ask return
is tracked upstream in Pi issue #9175).

## Decision contract

`piGuard(call)` returns `{ block: true, reason }` to stop the tool, or `undefined`
to allow it. For a prompt instead of a hard block, surface the reason through
`ctx.ui.confirm(reason)` in the hook (Pi's tri-state "ask").

## Requirements

- **node** on `PATH`.
- **xgrep** with `guard --command` (≥ 0.78) on `PATH` or via `XGREP_PATH` —
  [xgrep.ai](https://xgrep.ai) / [docs](https://mondoo.com/docs/xgrep) / `@mondoohq/xgrep` on npm.
- **cnspec** on `PATH` or via `CNSPEC_PATH` for the IaC leg (optional).

## Testing

`node --experimental-strip-types integrations/pi/smoke.test.ts` (or `npx tsx …`)
drives `piGuard` with a fake runner — block/allow for shell and code, correct
field mapping — with no binaries. The real binaries are covered by the shared
engine's scenario.
