# Secure your stack with AI agents

The tools AI coding agents use to secure software end to end — the **code they write** and the
**systems you run**. Two engines do the work: **xgrep** for code (SAST, SCA, secrets) and
**cnspec** for posture & policy (OS, cloud, SaaS, AI, and IaC). This repo layers three things
over them for an agent:

- **Skills** — outcome-named instruction packs in two families: *secure development* (the code
  lifecycle) and *secure posture* (the stack you run).
- **A runtime guard** — the `secure-guard` mod + per-agent adapters that check an agent's
  tool calls with both engines as it works.
- **An OWASP coverage spine** — [`docs/owasp.md`](docs/owasp.md) maps every capability to OWASP Top
  10:2025 and the OWASP Top 10 for LLM & GenAI 2025, honestly.

Compatible with Claude Code, Codex, Gemini CLI, Cursor, and more; skills follow the standardized
[Agent Skills](https://agentskills.io/home) format.

> [!TIP]
> If your agent doesn't support skills, you can use [`agents/SKILLS.md`](agents/SKILLS.md) directly as a fallback — it's a generated bundle of the skill instructions. To work *on* this repo, an agent should read the root [`AGENTS.md`](AGENTS.md) ([agents.md](https://agents.md/) convention).

## Installation

### Claude Code

Installing is a **two-step** flow — registering the marketplace makes the skills
*available*, but each skill is installed individually (opt-in), so you pull only the
ones you want.

1. Register the repository as a plugin marketplace (once):

```shell
/plugin marketplace add mondoohq/secure-stack
```

2. Install the skills you want:

```shell
# Secure development — the code lifecycle
/plugin install understand-code@secure-stack
/plugin install secure-coding@secure-stack
/plugin install secure-pipeline@secure-stack
/plugin install triage-findings@secure-stack
/plugin install fix-findings@secure-stack
/plugin install author-detections@secure-stack
# Secure posture — what you run
/plugin install secure-os@secure-stack
/plugin install secure-cloud@secure-stack
/plugin install secure-saas@secure-stack
/plugin install secure-ai-services@secure-stack
```

Or run `/plugin` and pick from **Browse plugins** interactively. Adding the marketplace
alone does **not** install anything — if `/plugin install …@secure-stack` reports
*"Marketplace not found"*, run step 1 first.

From a shell, the same works non-interactively with the `claude` CLI:

```shell
claude plugin marketplace add mondoohq/secure-stack
claude plugin install triage-findings@secure-stack
```

### Codex

1. Copy or symlink skills from this repository's `skills/` directory into one of Codex's standard `.agents/skills` locations (e.g., `$REPO_ROOT/.agents/skills` or `$HOME/.agents/skills`) as described in the [Codex Skills guide](https://developers.openai.com/codex/skills/).

2. Once available, Codex will discover the skill and load the `SKILL.md` instructions automatically.

3. If your Codex setup still relies on `AGENTS.md`, use the generated [`agents/SKILLS.md`](agents/SKILLS.md) file as a fallback bundle.

### Gemini CLI

Install locally:

```shell
gemini extensions install . --consent
```

Or use the GitHub URL:

```shell
gemini extensions install https://github.com/mondoohq/secure-stack.git --consent
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
/triage-findings
/author-detections
```

## Available Skills

<!-- BEGIN_SKILLS_TABLE -->
| Name | Description | Documentation |
|------|-------------|---------------|
| `author-detections` | Catch a pattern nothing else catches — author a custom, tested xgrep/Semgrep detection rule (including taint-mode dataflow), or port a rule to new languages | [SKILL.md](skills/author-detections/SKILL.md) |
| `fix-findings` | Fix xgrep security findings and prove each fix holds — one finding or a whole set (or the triage-confirmed true positives) — through the verify/apply harness | [SKILL.md](skills/fix-findings/SKILL.md) |
| `secure-ai-services` | Secure AI services and AI tooling — scan OpenAI, Anthropic, vLLM, Databricks AI, and vector stores with cnspec, and govern approved AI agents/IDE-extensions/MCP servers, mapped to the OWASP LLM Top 10 | [SKILL.md](skills/secure-ai-services/SKILL.md) |
| `secure-cloud` | Audit cloud account security posture — scan AWS, Azure, GCP, and Kubernetes against CIS foundations and Mondoo cloud policies with cnspec | [SKILL.md](skills/secure-cloud/SKILL.md) |
| `secure-coding` | Write it safely — avoid vulnerable patterns across 7 languages, aligned to OWASP Top 10:2025 and the OWASP Top 10 for LLM & GenAI 2025 | [SKILL.md](skills/secure-coding/SKILL.md) |
| `secure-os` | Audit and harden operating systems and network devices — scan a Linux/macOS/Windows host, container image, or network device against CIS/vendor benchmarks with cnspec | [SKILL.md](skills/secure-os/SKILL.md) |
| `secure-pipeline` | Verify and enforce security before code ships — scan code (SAST/SCA/secrets) with xgrep and IaC/config with cnspec, then triage and fix, mapped to OWASP Top 10:2025 and the OWASP Top 10 for LLM & GenAI 2025 | [SKILL.md](skills/secure-pipeline/SKILL.md) |
| `secure-saas` | Audit SaaS and identity-provider security posture — scan GitHub, GitLab, Okta, Google Workspace, Microsoft 365, Slack, Atlassian, and Snowflake with cnspec | [SKILL.md](skills/secure-saas/SKILL.md) |
| `triage-findings` | Decide whether a security finding is real — classify xgrep scan results as true or false positives by tracing dataflow and call chains with the code graph | [SKILL.md](skills/triage-findings/SKILL.md) |
| `understand-code` | Understand an unfamiliar codebase before you change it — map structure, find definitions/callers, trace call chains, and assess a change's blast radius with xgrep's AST code graph | [SKILL.md](skills/understand-code/SKILL.md) |
<!-- END_SKILLS_TABLE -->

## What's Included

### Secure development — the code lifecycle

Outcome-named skills, in the order you meet them (the root [`AGENTS.md`](AGENTS.md) maps the
full set of layers; the OWASP mapping lives in the [coverage matrices](docs/owasp.md)):

- **`understand-code`** — *understand it first*: map an unfamiliar codebase, find definitions/callers, trace call chains, assess a change's blast radius.
- **`secure-coding`** — *write it safely*: avoid vulnerable patterns while writing/reviewing code, aligned to OWASP Top 10:2025.
- **`secure-pipeline`** — *ship it safely*: scan → gate → fix across code (xgrep) and IaC/config (cnspec) before a change merges.
- **`triage-findings`** — *is it real?*: classify scan findings as true/false positives via code-graph dataflow.
- **`fix-findings`** — *fix it, provably*: remediate one finding or a whole set through the verify/apply harness.
- **`author-detections`** — *catch what nothing else catches*: author a custom, tested detection rule, or port one to new languages.

These drive the `xgrep` CLI (and `cnspec` for IaC); install xgrep via
[Getting Started](https://mondoo.com/docs/xgrep/getting-started/).

### Secure posture — what you run

Outcome-named skills that invoke [cnspec](https://github.com/mondoohq/cnspec) to audit the
posture of your running stack against CIS / vendor / OWASP frameworks. They need `cnspec`
([install](https://mondoo.com/docs/cnspec/install)) plus access/credentials to the target:

- **`secure-os`** — *hosts & devices*: scan a Linux/macOS/Windows host, container image, or network device against CIS/vendor benchmarks.
- **`secure-cloud`** — *cloud accounts*: scan AWS, Azure, GCP, and Kubernetes against CIS foundations and Mondoo cloud policies.
- **`secure-saas`** — *SaaS & identity*: scan GitHub, GitLab, Okta, Google Workspace, Microsoft 365, Slack, Atlassian, Snowflake.
- **`secure-ai-services`** — *AI*: scan OpenAI, Anthropic, vLLM, Databricks AI, vector stores, and govern approved AI agents / MCP servers.

### Runtime guard — as the agent works

The skills guide an agent; the **guard** checks it. This repo ships
[`secure-guard`](mods/secure-guard) — a mod that routes each tool call to the right
engine before it lands: **xgrep** for secrets/PII + dangerous commands (shell) and OWASP Top
10 / SAST / secrets (code), and **cnspec** for IaC policy (Terraform, Dockerfile, Kubernetes,
CloudFormation). The routing and finding logic lives once in a shared core/engine; each agent
gets a thin adapter under [`integrations/`](integrations/).

<!-- BEGIN_INTEGRATIONS_TABLE -->
| Agent | Shape | Install | Posture |
|-------|-------|---------|---------|
| **Claude Code** | in-process mod | `/plugin install secure-guard@secure-stack` | shell blocks; code/IaC advisory (post-write) |
| **OpenAI Codex** | external pre-tool hook | `node integrations/codex/install.mjs` | shell block or ask; code + IaC block (pre-write) |
| **Mistral Vibe** | external pre-tool hook | `node integrations/vibe/install.mjs` | shell + code + IaC deny (pre-write) |
| **Pi** | in-process TS extension | load `integrations/pi` as a Pi extension | block (pre-write); `ask` via `ctx.ui.confirm` |
| **opencode** | in-process TS plugin | copy `plugin.ts` into `.opencode/plugins/` | deny via throw (pre-write); no native `ask` |
<!-- END_INTEGRATIONS_TABLE -->

It needs `xgrep` (shell + code; auto-fetched from npm if not installed) and, for the IaC leg,
`cnspec` ([install](https://mondoo.com/docs/cnspec/install)). Everything is fail-open — a
missing or erroring scanner never wedges the agent. See [`integrations/README.md`](integrations/README.md)
for per-agent install and testing.

> xgrep also ships its own lightweight built-in hook (`xgrep guard install --agent claude|codex`,
> secrets/PII + dangerous-command only) — see [Guard hooks](https://mondoo.com/docs/xgrep/ai-agents/guard-hooks/).
> The `secure-guard` mod above is the richer, cross-agent, both-engines option.

## Standards

This repo follows two open specifications, with CI enforcing the parts that drift silently:

- **[AGENTS.md](https://agents.md/)** — the root [`AGENTS.md`](AGENTS.md) gives an agent the
  context and commands to work on this repo (one file, 25+ agents).
- **[Agent Skills](https://agentskills.io/specification)** — every skill under `skills/` is a
  spec-conformant `SKILL.md`; `./scripts/publish.sh --check` fails the build on a bad `name`,
  a name that doesn't match its directory, or an out-of-range `description`.

Verify the whole repo against both specs with [Mondoo's skillcheck](https://github.com/mondoohq/skillcheck)
— it runs an embedded MQL policy and needs no install beyond `npx`:

```shell
npx @mondoohq/skillcheck validate .
```

CI runs it on every pull request ([`.github/workflows/skillcheck-validate.yml`](.github/workflows/skillcheck-validate.yml)).
How we conform, the checklist for adding a skill, and the workflow:
[`docs/agents-and-skills.md`](docs/agents-and-skills.md).

## Releasing

All skills share one version, and you decide when it moves by merging a release
PR.

1. **Actions → Prepare Release**, pick `patch`, `minor`, or `major` (or type an
   explicit version like `2.0.0` or `2.0.0-rc.1`). Tick **dry run** first to see
   the computed version and release notes in the job summary without pushing
   anything.
2. It opens a **`chore: release vX.Y.Z`** PR with every manifest stamped, the
   `CHANGELOG.md` section written, and `agents/SKILLS.md` plus the README table
   regenerated. Review the diff — editing the notes here changes what the
   release page says.
3. **Merge it.** That is the release. `release.yml` sees the version change on
   `main`, mints the `vX.Y.Z` tag, and publishes the GitHub Release from
   `CHANGELOG.md`. No tag push, nothing else to run.

A version with a hyphen (`2.0.0-rc.1`) publishes flagged as a pre-release, so it
never becomes the repo's *Latest release*.

Afterwards, anyone with a skill installed picks it up with:

```shell
claude plugin update <skill>@secure-stack
```

> [!IMPORTANT]
> **Never edit a version by hand.** `claude plugin update` compares the version
> in a skill's `plugin.json` and skips the copy when it hasn't changed, so a
> version that doesn't move leaves everyone who installed the skill on old
> content indefinitely. `./scripts/publish.sh --check` fails if any manifest's
> version drifts from the root, and CI runs it on every pull request.

## Looking for the MQL skill?

> [!NOTE]
> The MQL skill lives in the cnspec repository, at
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

## License

Apache-2.0
