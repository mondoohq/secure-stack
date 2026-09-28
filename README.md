# Mondoo Skills

A collection of agent skills for [xgrep](https://mondoo.com/docs/xgrep/)-powered security work — code inspection, rule authoring, finding triage, and remediation. Compatible with Claude Code, Codex, Gemini CLI, and Cursor.

The skills in this repository follow the standardized [Agent Skills](https://agentskills.io/home) format.

> [!NOTE]
> **Looking for the MQL skill?** It lives in the cnspec repository, at
> [`mondoohq/cnspec/skills`](https://github.com/mondoohq/cnspec/tree/main/skills),
> next to the policy content it documents. `mondoo-mql` was mirrored here until it
> fell behind the maintained copy, so it has been removed rather than left to drift
> further. Install the current skills from cnspec:
>
> ```shell
> /plugin marketplace add mondoohq/cnspec
> /plugin install mql@cnspec-skills
> /plugin install policy-graph@cnspec-skills
> ```

> [!TIP]
> If your agent doesn't support skills, you can use [`agents/AGENTS.md`](agents/AGENTS.md) directly as a fallback.

## Installation

### Claude Code

Installing is a **two-step** flow — registering the marketplace makes the skills
*available*, but each skill is installed individually (opt-in), so you pull only the
ones you want.

1. Register the repository as a plugin marketplace (once):

```shell
/plugin marketplace add mondoohq/skills
```

2. Install the skills you want:

```shell
/plugin install xgrep-inspect@mondoohq/skills
/plugin install xgrep-rule-creator@mondoohq/skills
/plugin install xgrep-triage@mondoohq/skills
/plugin install xgrep-remediate@mondoohq/skills
/plugin install xgrep-fix@mondoohq/skills
/plugin install secure-coding@mondoohq/skills
```

Or run `/plugin` and pick from **Browse plugins** interactively. Adding the marketplace
alone does **not** install anything — if `/plugin install …@mondoohq/skills` reports
*"Marketplace not found"*, run step 1 first.

From a shell, the same works non-interactively with the `claude` CLI:

```shell
claude plugin marketplace add mondoohq/skills
claude plugin install xgrep-triage@mondoohq/skills
```

### Codex

1. Copy or symlink skills from this repository's `skills/` directory into one of Codex's standard `.agents/skills` locations (e.g., `$REPO_ROOT/.agents/skills` or `$HOME/.agents/skills`) as described in the [Codex Skills guide](https://developers.openai.com/codex/skills/).

2. Once available, Codex will discover the skill and load the `SKILL.md` instructions automatically.

3. If your Codex setup still relies on `AGENTS.md`, use the generated [`agents/AGENTS.md`](agents/AGENTS.md) file as a fallback bundle.

### Gemini CLI

Install locally:

```shell
gemini extensions install . --consent
```

Or use the GitHub URL:

```shell
gemini extensions install https://github.com/mondoohq/skills.git --consent
```

See [Gemini CLI extensions docs](https://geminicli.com/docs/extensions/#installing-an-extension) for more help.

### Cursor

This repository includes Cursor plugin manifests:

- `.cursor-plugin/plugin.json`
- `.cursor-plugin/marketplace.json`

Install from repository URL or local checkout via the Cursor plugin flow.

## Usage

The skills automatically activate when working on relevant tasks. You can also invoke them directly:

```shell
/xgrep-triage
/xgrep-rule
```

## Available Skills

<!-- BEGIN_SKILLS_TABLE -->
| Name | Description | Documentation |
|------|-------------|---------------|
| `secure-coding` | Secure coding guidance for AI agents - proactively avoid generating vulnerable code patterns across 7 languages | [SKILL.md](skills/secure-coding/SKILL.md) |
| `xgrep-fix` | Fix a whole set of xgrep findings — or just the triage-confirmed true positives in a findings.json — in one pass through the verify/apply harness | [SKILL.md](skills/xgrep-fix/SKILL.md) |
| `xgrep-inspect` | Navigate and understand source code using xgrep's AST-powered code intelligence | [SKILL.md](skills/xgrep-inspect/SKILL.md) |
| `xgrep-remediate` | Fix a confirmed xgrep finding safely using the verify/apply harness — apply deterministic fixes, author and verify assisted fixes against the fix contract, and surface advisory guidance | [SKILL.md](skills/xgrep-remediate/SKILL.md) |
| `xgrep-rule-creator` | Create custom xgrep rules for detecting security vulnerabilities and code patterns with test-first methodology | [SKILL.md](skills/xgrep-rule-creator/SKILL.md) |
| `xgrep-triage` | Investigate and classify xgrep scan findings using code graph analysis | [SKILL.md](skills/xgrep-triage/SKILL.md) |
<!-- END_SKILLS_TABLE -->

## What's Included

### xgrep Skills

A set of skills built on [xgrep](https://mondoo.com/docs/xgrep/), Mondoo's fast,
Semgrep-compatible SAST scanner, for security review and remediation workflows:

- **`xgrep-inspect`** - Navigate and understand source code using xgrep's AST-powered code intelligence
- **`xgrep-rule-creator`** - Create custom xgrep rules with a test-first methodology, or port rules to new languages
- **`xgrep-triage`** - Investigate and classify scan findings using code-graph analysis
- **`xgrep-remediate`** - Fix a confirmed finding safely using xgrep's verify/apply harness
- **`xgrep-fix`** - Fix a whole set of findings — or the true positives a triage report confirmed — in one pass
- **`secure-coding`** - Proactively avoid generating vulnerable code across 7 languages

These skills drive the `xgrep` CLI; install it by following
[Getting Started](https://mondoo.com/docs/xgrep/getting-started/) to use them.

### Runtime guardrail: `xgrep guard`

The skills help an agent write and review safer code. For a guardrail while the agent
works, xgrep also ships a hook for Claude Code and Codex. It checks every prompt and
tool call before it runs, blocking secrets or PII leaving the machine and dangerous
commands such as `curl … | sh` or a reverse shell. It runs locally, with no network
call.

```shell
xgrep guard install --agent claude --daemon   # or --agent codex; --daemon keeps a warm checker running
xgrep guard status
```

When the guard blocks an action, the agent should explain which rule fired and ask the
user how to proceed, never work around it. See
[Guard hooks](https://mondoo.com/docs/xgrep/ai-agents/guard-hooks/) in the xgrep docs.

## Releasing

All skills share one version, and you decide when it moves by merging a release
PR.

1. **Actions → Prepare Release**, pick `patch`, `minor`, or `major` (or type an
   explicit version like `2.0.0` or `2.0.0-rc.1`). Tick **dry run** first to see
   the computed version and release notes in the job summary without pushing
   anything.
2. It opens a **`chore: release vX.Y.Z`** PR with every manifest stamped, the
   `CHANGELOG.md` section written, and `agents/AGENTS.md` plus the README table
   regenerated. Review the diff — editing the notes here changes what the
   release page says.
3. **Merge it.** That is the release. `release.yml` sees the version change on
   `main`, mints the `vX.Y.Z` tag, and publishes the GitHub Release from
   `CHANGELOG.md`. No tag push, nothing else to run.

A version with a hyphen (`2.0.0-rc.1`) publishes flagged as a pre-release, so it
never becomes the repo's *Latest release*.

Afterwards, anyone with a skill installed picks it up with:

```shell
claude plugin update <skill>@mondoo-skills
```

> [!IMPORTANT]
> **Never edit a version by hand.** `claude plugin update` compares the version
> in a skill's `plugin.json` and skips the copy when it hasn't changed, so a
> version that doesn't move leaves everyone who installed the skill on old
> content indefinitely. `./scripts/publish.sh --check` fails if any manifest's
> version drifts from the root, and CI runs it on every pull request.

## License

Apache-2.0
