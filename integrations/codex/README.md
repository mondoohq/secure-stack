# secure-guard for OpenAI Codex

Runs Mondoo's scanners as a **pre-tool hook** in Codex: before Codex runs a shell
command or writes a file, the hook checks it and can block the call.

- **Shell** — the proposed Bash command goes to `xgrep guard --command`; a
  secret/PII leak or a dangerous command is **blocked**.
- **Write (code)** — the proposed file content is scanned with `xgrep scan`
  (OWASP Top 10 / SAST / secrets); a high-confidence finding **blocks** the write.
- **Write (IaC)** — Terraform / Dockerfile / Kubernetes / CloudFormation content is
  policy-checked with `cnspec`; a failed policy **blocks** the write.

Everything else runs. The hook is **fail-open**: if a scanner is missing, too old,
or errors, the call is allowed — the guard never wedges your session.

> Codex hooks fire *before* the tool, so this guard is preventive (it blocks
> writing vulnerable code), unlike the Claude mod's advisory post-write review.
> Edit/MultiEdit deliver only a fragment pre-tool, so code review there is left to
> the shell + Write legs.

## Install

```bash
node integrations/codex/install.mjs            # into the current project
node integrations/codex/install.mjs /path/repo # or a specific project
```

This writes/merges `.codex/hooks.json` with a `PreToolUse` entry that runs the
shared hub command `integrations/shared/hook.mjs --agent codex`. Re-running is
idempotent.

## Requirements

- **node** on `PATH`.
- **xgrep** on `PATH` (or `XGREP_PATH=/path/to/xgrep`), new enough to support
  `guard --command` (≥ 0.78). Get it from [xgrep.ai](https://xgrep.ai) /
  [docs](https://mondoo.com/docs/xgrep) / the `@mondoohq/xgrep` npm package.
- **cnspec** on `PATH` (or `CNSPEC_PATH`) for the IaC leg — optional; without it the
  IaC check stays silently off. See the mod README for the policy-bundle options.

## Decision contract

The hook reads the tool event as JSON on **stdin** and, when it blocks, writes one
JSON line to **stdout**:

```json
{"decision":"block","reason":"secure-guard: <summary>. Do not retry unless the user asks."}
```

No output means **allow**. (`"ask"` is also supported if you prefer a prompt over a
hard block.)
