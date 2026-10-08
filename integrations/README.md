# Agent integrations

The `secure-guard` runs the same two engines — **xgrep** (secrets/PII + dangerous
commands, and OWASP Top 10 / SAST / secrets on code) and **cnspec** (IaC policy) — across
coding agents. The decision and formatting logic lives once in
[`../mods/secure-guard/hooks/core.mjs`](../mods/secure-guard/hooks/core.mjs) (pure)
and [`shared/engine.mjs`](./shared/engine.mjs) (routing + scanner I/O); each adapter here only
translates that agent's tool-event in and decision out.

| Agent | Shape | Adapter | Posture |
|---|---|---|---|
| **Claude Code** | in-process mod | [`../mods/secure-guard`](../mods/secure-guard) | shell blocks; code/IaC **advisory** (post-write) |
| **OpenAI Codex** | external pre-tool hook (`.codex/hooks.json`) | [`codex/`](./codex) → `shared/hook.mjs --agent codex` | shell + code + IaC **block** (pre-write) |
| **Mistral Vibe** | external pre-tool hook (`.vibe/hooks.toml`) | [`vibe/`](./vibe) → `shared/hook.mjs --agent mistral` | shell + code + IaC **deny** (pre-write) |
| **Pi** | in-process TS extension (`tool_call`) | [`pi/`](./pi) → `piGuard` over `shared/engine.mjs` | shell + code + IaC **block** (pre-write); `ask` via `ctx.ui.confirm` |
| **opencode** | in-process TS plugin (`tool.execute.before`) | [`opencode/`](./opencode) → `opencodeGuard` over `shared/engine.mjs` | shell + code + IaC **deny** (throw); no native `ask` |

## The engine and the adapters

[`shared/engine.mjs`](./shared/engine.mjs) is the one place that turns a neutral tool event
into a decision by driving the scanners:

- **Bash / shell** → `xgrep guard --command <cmd>` → deny on a secret/PII leak or dangerous command.
- **Write (code)** → scans the *proposed* content with `xgrep scan` → deny on a high-confidence finding.
- **Write (IaC)** → policy-checks the *proposed* Terraform / Dockerfile / K8s / CloudFormation with `cnspec` → deny on a failed policy.

`evaluate(event)` returns a neutral `{ decision: "allow" | "deny", reason }`. The scanners run
through an injectable runner, so routing is unit-tested without binaries. Each adapter maps
its agent's event to the neutral shape (`toEvent`) and surfaces the decision in that agent's
form:

- **External-hook agents** ([`shared/hook.mjs`](./shared/hook.mjs)) read the event as JSON on
  **stdin** and write the decision to **stdout** (no output = allow). `--agent` selects the
  wire format (`formatDecision`): Codex `{"decision":"block"|"ask","reason"}`, Vibe
  `{"decision":"deny","reason"}`.
- **In-process agents** import `evaluate` directly: Pi returns `{ block: true, reason }`,
  opencode **throws** `Error(reason)`.

### Pre-tool vs. post-tool

External hooks fire *before* the tool, so for a Write they scan the proposed content and can
**block** vulnerable code from ever landing — stricter than the Claude mod's advisory
post-write review. Edit/MultiEdit deliver only a fragment pre-tool, so code review there is
left to the shell + Write legs.

Everything is **fail-open**: a missing, too-old, or erroring scanner (or a timeout) allows the
call — a guard must never wedge the session.

## Requirements

- **node** on `PATH`.
- **xgrep** with `guard --command` (≥ 0.78) on `PATH` or via `XGREP_PATH` —
  [xgrep.ai](https://xgrep.ai) / [docs](https://mondoo.com/docs/xgrep) / `@mondoohq/xgrep` on npm.
  Without one, every adapter fetches the release the Claude mod pins, via `npx`, visibly.
- **cnspec** on `PATH` or via `CNSPEC_PATH` for the IaC leg (optional). By default it runs the
  latest public policy bundles, downloaded when it scans: only policies come down, and the file
  is assessed locally with nothing uploaded. See the
  [mod README](../mods/secure-guard/README.md#where-the-iac-policies-come-from) for the other
  sources (`CNSPEC_POLICY_BUNDLE`, offline `CNSPEC_CONTENT_DIR`, opt-in `CNSPEC_USE_PLATFORM`).

## Testing

- Unit (no binaries): `node --test integrations/shared/*.test.mjs` — engine routing (fake
  runner), event parsing, and per-agent formatting.
- Adapter smoke (no binaries): `node --experimental-strip-types integrations/pi/smoke.test.ts`
  and `integrations/opencode/smoke.test.ts` (or `npx tsx …`) drive `piGuard` / `opencodeGuard`
  with a fake runner.
- End-to-end: `node integrations/shared/pipeline-scenario.mjs` drives the real `hook.mjs`
  against the real binaries for the external-hook agents (shell deny/allow, code block/allow,
  IaC block). Point it at binaries with `XGREP_PATH` / `CNSPEC_PATH` to skip the download.
