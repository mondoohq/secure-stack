# AGENTS.md

Working instructions for an AI agent operating in **this** repository. (This is the
[agents.md](https://agents.md/) entry point. If you are an agent being *used* by someone
else and your runtime can't load `SKILL.md` skills, read [`agents/SKILLS.md`](agents/SKILLS.md)
instead — that's the generated bundle of the skill instructions.)

## What this repo is

The source for tools AI coding agents use to secure a stack end to end — the code they write
and the systems you run — powered by **xgrep** (code) and **cnspec** (posture & policy). Three
layers:

- **`skills/`** — loadable [Agent Skills](https://agentskills.io/specification), outcome-named,
  in two families:
  - *secure development* (code lifecycle): `understand-code` → `secure-coding` →
    `secure-pipeline` → `triage-findings` → `fix-findings`, plus `author-detections`.
  - *secure posture* (what you run): `secure-os`, `secure-cloud`, `secure-saas`,
    `secure-ai-services` — thin wrappers that invoke cnspec.
- **`mods/secure-guard/`** + **`integrations/`** — a runtime guard that scans an agent's
  tool calls with **xgrep** (code/secrets/dangerous commands) and **cnspec** (IaC policy)
  before they land, with a thin adapter per agent (Claude, Codex, Vibe, Pi, opencode).
- **`docs/owasp.md`** — the OWASP Top 10:2025 (app) and LLM/GenAI 2025 coverage matrices the
  hub is measured against.

Full layout and spec conformance: [`docs/agents-and-skills.md`](docs/agents-and-skills.md).

## Build, validate, test

No compile step. Node (for the mod/adapters) and `npx tsx` (for the scripts) are the only
tooling.

```bash
# Regenerate agents/SKILLS.md + the README tables, and validate every manifest.
./scripts/publish.sh            # write generated artifacts
./scripts/publish.sh --check    # CI gate: fails if artifacts are stale or a manifest drifts

# Guard mod + adapters — unit tests (no scanner binaries needed):
node --test mods/secure-guard/hooks/*.test.mjs integrations/shared/*.test.mjs
node --experimental-strip-types integrations/pi/smoke.test.ts
node --experimental-strip-types integrations/opencode/smoke.test.ts

# End-to-end against the real binaries (point at installed tools to skip the download):
XGREP_PATH=/path/to/xgrep CNSPEC_PATH=/path/to/cnspec \
  node integrations/shared/pipeline-scenario.mjs
```

Always run `./scripts/publish.sh --check` before opening a PR — it is the CI gate.

## Conventions

- **Skills follow the Agent Skills spec**; the repo follows agents.md. Keep both true — see
  [`docs/agents-and-skills.md`](docs/agents-and-skills.md), including the "adding a new skill"
  checklist. A skill's `name` must equal its directory name.
- **`agents/SKILLS.md` is generated** — never hand-edit it; run `./scripts/publish.sh`.
- **One version for everything**, stamped by the release workflow. Never edit a `version` in
  any `plugin.json`/manifest by hand (`plugin update` skips unchanged versions, stranding
  users on old content). The README "Releasing" section is the process.
- **xgrep** is available to everyone — link it from its home at [xgrep.ai](https://xgrep.ai),
  the [docs](https://mondoo.com/docs/xgrep), or the `@mondoohq/xgrep` npm package, so readers
  can get started right away. **cnspec** is open source — link
  [github.com/mondoohq/cnspec](https://github.com/mondoohq/cnspec).
- **Small, focused commits** on feature branches; keep generated artifacts in the same commit
  as the change that caused them.

## Security

- The guard is **fail-open**: a missing, old, or erroring scanner must never wedge a session —
  preserve that in any adapter change.
- Don't commit secrets or real credentials, and don't add a scanner invocation that sends code
  off the machine. xgrep/cnspec run locally.

## PR guidelines

Keep a PR to one feature. Run the tests and `./scripts/publish.sh --check` first, and state in
the description what you verified.
