# secure-guard for Mistral Vibe

Runs Mondoo's scanners as a **pre-tool hook** in Vibe: before Vibe runs a shell
command or writes a file, the hook checks it and can deny the call.

- **Shell** — the proposed command goes to `xgrep guard --command`; a secret/PII
  leak or a dangerous command is **denied**.
- **Write (code)** — the proposed content is scanned with `xgrep scan` (OWASP Top
  10 / SAST / secrets); a high-confidence finding **denies** the write.
- **Write (IaC)** — Terraform / Dockerfile / Kubernetes / CloudFormation content is
  policy-checked with `cnspec`; a failed policy **denies** the write.

Everything else runs. The hook is **fail-open**: a missing/old/erroring scanner
allows the call — the guard never wedges your session.

> Vibe hooks fire *before* the tool, so this guard is preventive. Vibe has no
> "ask" channel in the hook, so a risky call is denied with a reason rather than
> prompted; use Vibe's own permission config if you want an interactive prompt.

## Install

```bash
node integrations/vibe/install.mjs            # into the current project
node integrations/vibe/install.mjs /path/repo # or a specific project
```

This writes/merges `.vibe/hooks.toml` with a `[[pre_tool]]` block that runs the
shared hub command `integrations/shared/hook.mjs --agent mistral`. Re-running is
idempotent; delete the marked block to uninstall.

## Requirements

- **node** on `PATH`.
- **xgrep** on `PATH` (or `XGREP_PATH`), new enough for `guard --command` (≥ 0.78) —
  [xgrep.ai](https://xgrep.ai) / [docs](https://mondoo.com/docs/xgrep) / the
  `@mondoohq/xgrep` npm package.
- **cnspec** on `PATH` (or `CNSPEC_PATH`) for the IaC leg — optional.

## Decision contract

The hook reads the tool event as JSON on **stdin** and, when it denies, writes one
JSON line to **stdout**:

```json
{"decision":"deny","reason":"secure-guard: <summary>. Do not retry unless the user asks."}
```

No output means **allow**.
