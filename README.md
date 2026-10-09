# Secure Stack

**Security checks for AI coding agents, on your machine, while the agent works.**

![Secure Stack holding a piped remote installer in Claude Code until the user decides](mods/secure-guard/demo.gif)

Your coding agent runs shell commands, writes code, and changes infrastructure faster than
anyone can review it. Secure Stack puts Mondoo's security engines into the agent's loop —
[**xgrep**](https://xgrep.ai) for code and [**cnspec**](https://github.com/mondoohq/cnspec)
for configuration and posture — so risky actions are caught *before* they do damage, and
the agent fixes what it got wrong while it is still working on it.

## What it does for you

### Stops risky commands before they run

Every shell command the agent wants to run is checked first. A remote script piped into a
shell, an API token or a customer's SSN in the command, your credential files or environment
about to be sent to a remote host, an `rm -rf` of your home directory, a force-push to `main`:
the command is **held** and you choose Proceed or Cancel (above). Everything else runs without
a prompt, and you can [tune what is held](mods/secure-guard/README.md#tuning-the-guard).

### Catches vulnerabilities as code is written — and gets them fixed

After every file the agent writes or edits, xgrep reviews it: SQL and command injection,
XSS, path traversal, SSRF, insecure deserialization, weak crypto, hard-coded secrets.
Terraform, Dockerfiles, Kubernetes and CloudFormation get cnspec's policy checks.
Findings go straight back to the agent, which fixes them in the same turn, and the transcript
tells you what was caught.

![Secure Stack's inline review catching a SQL injection that Claude then fixes](mods/secure-guard/demo-inline-review.gif)

<sub>Asked only for a <code>/health</code> endpoint, Claude edits <code>app.py</code>; Mondoo xgrep
flags the SQL injection already in <code>/user</code>, and Claude fixes it before the turn ends.</sub>

### Security work on demand, in plain words

Skills teach the agent to drive the same engines for bigger jobs:

| Ask your agent | It uses |
|----------------|---------|
| *"Scan this repo for vulnerabilities before I merge."* | `secure-pipeline` |
| *"Is the SQL injection finding in `api/users.go` real?"* | `triage-findings` |
| *"Fix the confirmed findings and show each fix holds."* | `fix-findings` |
| *"Where is user input validated in this service, and what calls it?"* | `understand-code` |
| *"Write a rule that catches our unsafe `exec` wrapper."* | `author-detections` |
| *"Audit my AWS account against CIS."* | `secure-cloud` |
| *"Check our GitHub org's security settings."* | `secure-saas` |

### Private by design

Every scan runs on your machine. Your code and commands are never uploaded, nothing is
evaluated server-side, and there's no per-command network round-trip slowing the agent down.
The only downloads are the scanner and public policies, each announced when it happens
([details](mods/secure-guard/README.md#local-by-design)). When xgrep flags correct code, the
agent can report the false positive with a reproducible case — you review the exact issue and
nothing is sent unless you file it.

## Get started (Claude Code)

```shell
/plugin marketplace add mondoohq/secure-stack
/plugin install secure-guard@secure-stack      # checks commands and code as the agent works
/plugin install secure-pipeline@secure-stack   # scan → triage → fix before you merge
```

The guard is active from your next session — run `/secure-guard` to see it reach its
scanners. It fetches xgrep on first use if it isn't installed (announced, never silent);
install [cnspec](https://mondoo.com/docs/cnspec/install) as well to add the IaC checks. Then
work as usual, or ask for something from the table above. Other agents:
[Works with your agent](#works-with-your-agent).

## What it covers

| Area | What gets checked | When | Engine |
|------|-------------------|------|--------|
| **Code** | Injection (SQL, command, code), XSS, path traversal, SSRF, insecure deserialization, weak crypto — taint analysis in ~38 languages · hard-coded secrets (166 families) | as the agent writes it | xgrep |
| **Dependencies** | Known-vulnerable packages (SCA, 12+ ecosystems) · SBOM / CBOM / AIBOM | on demand (`secure-pipeline`) | xgrep |
| **Infrastructure as code** | Terraform, CloudFormation, Dockerfile, Kubernetes against 89 policy bundles | as the agent writes it | cnspec |
| **Commands** | Pipe-to-shell installers, reverse shells · secrets and PII in the command · credential files, env dumps and secret env vars sent to a remote host · `rm -rf` of home or root, force-push to protected branches, `DROP DATABASE`, `chmod -R 777` on system paths | before they run | xgrep |
| **Systems you run** | Linux / macOS / Windows hosts, container images, network devices · AWS, Azure, GCP, Kubernetes · GitHub, GitLab, Okta, Google Workspace, Microsoft 365, Slack, Atlassian, Snowflake · OpenAI, Anthropic, vLLM, Databricks AI, vector stores, approved agents and MCP servers | on demand (skills) | cnspec |

Measured against **OWASP Top 10:2025** — 8 of 10 categories covered strongly, A10 partially,
and A06 *Insecure Design* stated plainly as out of reach for static tools — and the **OWASP Top
10 for LLM & GenAI 2025**. Every claim is in the [coverage matrices](docs/owasp.md), with the
honest gaps.

## Works with your agent

| Agent | Skills | Runtime guard |
|-------|--------|---------------|
| **Claude Code** | ✅ plugin marketplace | ✅ `secure-guard` mod — holds commands, reviews code after each write |
| **OpenAI Codex** | ✅ `.agents/skills` | ✅ pre-tool hook — blocks (or asks) before the tool runs |
| **Gemini CLI** | ✅ extension | — |
| **Cursor** | ✅ plugin manifests | — |
| **Mistral Vibe**, **Pi**, **opencode** | — | ✅ pre-tool hook / extension / plugin |

Step-by-step setup for each is under [Installation](#installation); the guard's per-agent
details are in [`integrations/`](integrations/README.md). If your agent doesn't load skills,
[`agents/SKILLS.md`](agents/SKILLS.md) is the same instructions as one file.

## Installation

### Claude Code

Installing is a **two-step** flow — registering the marketplace makes the skills and the guard
*available*, but each is installed individually (opt-in), so you pull only the ones you want.

1. Register the repository as a plugin marketplace (once):

```shell
/plugin marketplace add mondoohq/secure-stack
```

2. Install what you want:

```shell
# Runtime guard — checks the agent's tool calls as it works
/plugin install secure-guard@secure-stack
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

For the runtime guard in Codex, run `node integrations/codex/install.mjs` ([details](integrations/codex/README.md)).

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


## Reference

### All skills

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

Two families: *secure development* follows the code lifecycle (understand → write → ship →
triage → fix, plus authoring detections) and drives xgrep (and cnspec for IaC); *secure
posture* audits what you run with cnspec and needs credentials to the target. Install xgrep
via [Getting Started](https://mondoo.com/docs/xgrep/getting-started/) and cnspec via its
[install guide](https://mondoo.com/docs/cnspec/install). Invoke a skill directly with
`/<name>`, e.g. `/triage-findings`.

### The runtime guard

[`secure-guard`](mods/secure-guard) routes each tool call to the right engine before it lands:
xgrep for shell commands and code, cnspec for IaC. The routing and finding logic lives once in
a shared core; each agent gets a thin adapter under [`integrations/`](integrations/).

<!-- BEGIN_INTEGRATIONS_TABLE -->
| Agent | Shape | Install | Posture |
|-------|-------|---------|---------|
| **Claude Code** | in-process mod | `/plugin install secure-guard@secure-stack` | shell held until you choose Proceed / Cancel; code + IaC findings fed back after the write |
| **OpenAI Codex** | external pre-tool hook | `node integrations/codex/install.mjs` | shell block or ask; code + IaC block (pre-write) |
| **Mistral Vibe** | external pre-tool hook | `node integrations/vibe/install.mjs` | shell + code + IaC deny (pre-write) |
| **Pi** | in-process TS extension | load `integrations/pi` as a Pi extension | block (pre-write); `ask` blocks too until a `ctx.ui.confirm` prompt is wired |
| **opencode** | in-process TS plugin | copy `plugin.ts` into `.opencode/plugins/` | deny via throw (pre-write); no native `ask` |
<!-- END_INTEGRATIONS_TABLE -->

Everything is fail-open — a missing or erroring scanner never wedges the agent. xgrep also
ships a lightweight built-in hook (`xgrep guard install --agent claude|codex`, secrets/PII and
dangerous commands only — see [Guard hooks](https://mondoo.com/docs/xgrep/ai-agents/guard-hooks/));
`secure-guard` is the richer, cross-agent, both-engines option.

## Contributing

### Standards

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

### Releasing

All skills and the `secure-guard` mod share one version, and you decide when it moves by
merging a release PR.

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

Afterwards, anyone with a skill or the guard installed picks it up with:

```shell
claude plugin update <plugin>@secure-stack
```

> [!IMPORTANT]
> **Never edit a version by hand.** `claude plugin update` compares the version
> in a plugin's `plugin.json` and skips the copy when it hasn't changed, so a
> version that doesn't move leaves everyone who installed it on old content
> indefinitely. `./scripts/publish.sh --check` fails if any manifest's version
> drifts from the root, and CI runs it on every pull request.

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
