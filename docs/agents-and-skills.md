# Following the AGENTS.md and Agent Skills specifications

This repository is a multi-agent distribution: its content (skills, the guard mod, the
adapters) is consumed by many coding agents, and the repo itself is meant to be worked on by
agents. It conforms to two open specifications, and CI enforces the parts that can drift
silently. This page is the contributor guide for keeping that true.

- **[AGENTS.md](https://agents.md/)** — the cross-agent convention for *instructions to an
  agent working in a repository*.
- **[Agent Skills](https://agentskills.io/specification)** — the `SKILL.md` format for
  *packaged, loadable skills*.

## Two files named AGENTS.md — different jobs

They are easy to confuse. Keep the distinction clear:

| File | Spec | Audience | How it's produced |
|------|------|----------|-------------------|
| **`/AGENTS.md`** (root) | agents.md | an agent **working on this repo** (a contributor) | hand-written |
| **`/agents/SKILLS.md`** | — (a bundle) | an agent **consuming** the skills that **can't load `SKILL.md`** | **generated** by `scripts/generate_agents.ts` |

The root file is the agents.md entry point (overview, build/validate/test, conventions). The
`agents/` file is a portable fallback bundle of the skill instructions — referenced by
`gemini-extension.json` (`contextFileName`) and offered in the README for agents without a
skills loader. Never hand-edit `agents/SKILLS.md`; regenerate it with `./scripts/publish.sh`.

## AGENTS.md (agents.md)

Rules we follow:

- **Lives at the repo root.** Agents auto-discover the nearest `AGENTS.md` up the directory
  tree; root is the canonical location. (We don't nest per-directory files today, but the
  convention allows it — a nested `AGENTS.md` overrides the root for that subtree.)
- **No required fields**; standard Markdown. We use the recommended sections: project
  overview, build/validate/test commands, code style & conventions, security, and
  contribution/PR guidelines.
- **It's living documentation and may be executed.** Agents may run the commands it lists, so
  the build/test commands must be correct and safe to run.
- **Explicit user prompts override it**, and it is compatible across 25+ agents (Claude,
  Codex, Cursor, Gemini, Copilot, …) — one file, many agents.

## Agent Skills (`SKILL.md`)

Every directory under `skills/` is one skill and must satisfy the spec:

### Directory layout

```
skills/<name>/
├── SKILL.md            # required: YAML frontmatter + Markdown instructions
├── references/         # optional: docs loaded on demand (keep each focused)
├── scripts/            # optional: executable helpers
├── assets/             # optional: templates/resources
└── .claude-plugin/
    └── plugin.json     # this repo's release-version manifest (see Releasing)
```

### `SKILL.md` frontmatter

| Field | Required | Rule we enforce |
|-------|----------|-----------------|
| `name` | **yes** | 1–64 chars; lowercase `a-z0-9` and single hyphens; no leading/trailing/`--`; **must equal the directory name** |
| `description` | **yes** | 1–1024 chars, non-empty; says *what it does and when to use it*, with keywords an agent matches on |
| `license` | no | license name or bundled-file reference |
| `compatibility` | no | ≤500 chars; environment requirements (most skills omit it) |
| `metadata` | no | string→string map for extra properties |
| `allowed-tools` | no | space-separated pre-approved tools (experimental; e.g. `Bash Read Edit Glob Grep`) |

### Body & progressive disclosure

Agents load a skill in three stages — metadata (~100 tokens, always), the full `SKILL.md`
body (on activation; keep it **under ~500 lines / 5000 tokens**), then `references/` and
`scripts/` files **only when needed**. So:

- Keep `SKILL.md` lean; move detail into `references/*.md`.
- Reference bundled files with relative paths one level deep (`references/REFERENCE.md`), or
  the skill's `{baseDir}` placeholder where supported.

## What CI enforces

`scripts/generate_agents.ts` (run by `./scripts/publish.sh --check` on every PR) fails the
build on:

- **Skills spec** — a `name` that isn't a valid slug, doesn't match its directory, or a
  missing/over-long `description`; and a `skills/<dir>/SKILL.md` whose frontmatter doesn't
  parse into a usable skill (it would otherwise be silently dropped from the bundle).
- **Marketplace sync** — every skill has a matching `.claude-plugin/marketplace.json` entry
  and vice-versa, names agreeing.
- **One version everywhere** — every `plugin.json` and sibling manifest carries the repo-wide
  version (see the README "Releasing" section; never edit a version by hand).
- **Integrations** — every `secure-guard` adapter listed in the generator exists on disk
  with its entry file and README.

Validate a single skill against the upstream reference tool:

```bash
# https://github.com/agentskills/agentskills/tree/main/skills-ref
skills-ref validate ./skills/<name>
```

## Verifying with skillcheck

For a quick check of the whole repo against both specs — the same `name`/`description`/
`name == directory` rules plus "a root `AGENTS.md` exists" and "`marketplace.json` lists
plugins" — use [Mondoo's skillcheck](https://github.com/mondoohq/skillcheck). It needs no
install beyond `npx`, and the rules are an embedded MQL policy (so the check is data, not a
reimplementation):

```bash
npx @mondoohq/skillcheck validate .
# → one ✓/✗ per rule; exits non-zero if any fail. Add --json for machine-readable output.
```

This complements `./scripts/publish.sh --check`: `publish.sh` owns the artifact generation,
marketplace sync, and the one-version check; `skillcheck validate` is the portable
spec/contract gate (and the same policy runs under `cnspec` for anyone already using it).

### As a GitHub workflow

CI runs it on every pull request via
[`.github/workflows/skillcheck-validate.yml`](../.github/workflows/skillcheck-validate.yml).
To add the same gate to another skills repository, drop in:

```yaml
name: skillcheck validate
on:
  pull_request:
    paths: ["skills/**", "AGENTS.md", ".claude-plugin/marketplace.json"]
  push:
    branches: [main]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "22"
      - run: npx -y @mondoohq/skillcheck validate .
```

Requires `@mondoohq/skillcheck` **>= v0.3.0** (the release that adds the `validate`
subcommand).

## Adding a new skill (checklist)

1. `skills/<name>/SKILL.md` with valid frontmatter (`name` == `<name>`, a keyworded
   `description`); body under ~500 lines, detail in `references/`.
2. `skills/<name>/.claude-plugin/plugin.json` with `"name": "<name>"` and the repo-wide
   `version` (the release workflow stamps it; match the current root version).
3. An entry in `.claude-plugin/marketplace.json`.
4. `./scripts/publish.sh` to regenerate `agents/SKILLS.md` and the README table, then
   `./scripts/publish.sh --check` to confirm everything is consistent.
5. If the skill is user-facing, add it to the README install list and "What's Included".
