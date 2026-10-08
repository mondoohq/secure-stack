# Changelog

## v2.0.1 - 2026-10-08

- fix(release): give the release job contents:write via the top-level permissions (#25)


## v2.0.0 - 2026-10-08

Renames the hub to **secure-stack** and reorganizes it around outcomes — two
skill families (secure development + secure posture), a runtime `secure-guard`
mod across five agents, and a single OWASP coverage page.

### ⚠️ Breaking — reinstall under the new names

Existing installs keep working but stop receiving updates under the old names.

- **Marketplace / repo:** `mondoohq/skills` → `mondoohq/secure-stack` (the old
  path still redirects). Re-add it: `/plugin marketplace add mondoohq/secure-stack`.
- **Skills renamed** (install with `…@secure-stack`): `xgrep-inspect` →
  `understand-code`, `xgrep-triage` → `triage-findings`, `xgrep-remediate` +
  `xgrep-fix` → `fix-findings` (merged), `xgrep-rule-creator` →
  `author-detections`, `secure-development` → `secure-pipeline`.
- **Runtime guard mod renamed:** `secure-dev-guard` → `secure-guard`.

### New

- Secure posture skills: `secure-os`, `secure-cloud`, `secure-saas`, `secure-ai-services`.
- A runtime `secure-guard` mod with adapters for Claude, Codex, Mistral Vibe, Pi, and opencode.
- A single OWASP Top 10 2025 coverage page (`docs/owasp.md`, app + LLM/GenAI).
- An optional Slack release notification.

### Commits

- docs(readme): move the MQL-skill note from the top to its own section near the end (#22)
- ci(release): optional Slack release notification (ported from skillcheck) (#21)
- fix(secure-guard): unify cnspec JSON parsing behind a never-throwing parseJsonObject (#20)
- Secure your stack with AI agents: restructure the hub (secure-stack) (#19)
- docs: point agents at xgrep guard and say what to do when it blocks (#18)

## v1.0.1 - 2026-09-07

- feat: release by merging a release PR, and fix a release that cannot run (#16)
- feat: add a release workflow that stamps versions and writes a changelog (#15)
- chore: remove the obsolete mondoo-mql skill, point to cnspec (#14)
- xgrep-rule-creator: the cost model for taint rules (#13)
- docs: make skill docs self-contained (#12)
- xgrep-rule-creator: document the silent-failure anti-patterns (#11)
- docs(readme): make the two-step Claude Code install explicit + list all skills (#10)
- feat: add xgrep security skills to the marketplace (#9)
- ✨ Update skill to use cnspec CLI for schema discovery (#8)
- refactor: rename mql-dev skill to mondoo-mql (#7)
- feat: add Codex support and update README with multi-agent installation (#6)
- feat: add Gemini CLI support (#5)
- feat: add Cursor IDE support (#4)
- ci: add workflow to validate generated artifacts on PRs (#3)
- Add automation scripts for AGENTS.md generation (#2)
- Flatten directory structure (#1)
- docs: update README with installation and usage instructions
- fix: restructure for marketplace plugin format
- fix: correct marketplace.json schema
- fix: add marketplace.json for plugin marketplace installation
- feat: add mql-dev skill for MQL development and MCP tools
- Initial plugin structure for secure-stack

