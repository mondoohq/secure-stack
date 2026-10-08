---
name: secure-pipeline
description: Verify and enforce security before code ships — scan code (SAST/SCA/secrets) with xgrep and infrastructure/config (Terraform, Dockerfile, Kubernetes, CloudFormation) with cnspec, then triage and fix findings, mapped to OWASP Top 10:2025 and the OWASP Top 10 for LLM & GenAI 2025. Use to gate a change, wire a CI check, or run a pre-merge/pre-ship security pass across code, dependencies, secrets, and IaC.
allowed-tools: Bash Read Edit Glob Grep
---

# Secure Pipeline

The **verify-and-enforce** half of secure development: once code is written, prove it is safe
before it ships. Where the `secure-coding` skill helps **write** code safely, this skill
**scans, gates, and fixes** across everything a change touches — code, dependencies, secrets,
and infrastructure/config — and maps the result to the OWASP standards the work is measured
against. Two engines do the scanning:

- **xgrep** — SAST (taint, ~38 languages), SCA (dependency vulnerabilities), secrets, and
  SBOM/CBOM/AIBOM, on **code**. [xgrep.ai](https://xgrep.ai) · [docs](https://mondoo.com/docs/xgrep).
- **cnspec** — policy-as-code for **configuration / IaC / cloud** (Terraform, CloudFormation,
  Dockerfile, Kubernetes). [github.com/mondoohq/cnspec](https://github.com/mondoohq/cnspec).

## When to use

- Gating a change before merge or release (a pre-commit / CI security pass).
- Scanning code the agent just wrote or edited for SAST / SCA / secrets issues.
- Policy-checking IaC/config the agent produced.
- Triaging findings and applying fixes.

For **writing** secure code in the first place, use `secure-coding`. For the full map of the
hub's layers, see the root [`AGENTS.md`](../../AGENTS.md).

## The pipeline, stage by stage

| Stage | Do | Tool / skill |
|-------|-----|--------------|
| **Scan code** | SAST + SCA + secrets over the change | `xgrep scan` (below) |
| **Scan IaC / config** | policy-check Terraform / CFN / Dockerfile / K8s | `cnspec scan` (below) |
| **Triage** | classify true vs false positives | `triage-findings` skill |
| **Fix** | remediate a finding / a whole set | `fix-findings` skill |
| **Guard at runtime** | block risky tool calls as the agent works | the `secure-guard` mod ([mods](../../mods/secure-guard)) |

## Scan code — xgrep

```bash
xgrep scan .                               # SAST + SCA + secrets over the tree
xgrep scan path/to/file.py --json          # one file, machine-readable
xgrep scan . --owasp --owasp-edition 2025  # live OWASP Top 10:2025 coverage scoreboard
```

Hand findings to `triage-findings` → `fix-findings`. Install xgrep via
[Getting Started](https://mondoo.com/docs/xgrep/getting-started/).

## Scan IaC / config — cnspec (reference + invoke)

cnspec is a separate tool this skill **invokes**; it has its own skills for *authoring* MQL
policy — don't duplicate them. For authoring, point at
[`mondoohq/cnspec/skills`](https://github.com/mondoohq/cnspec/tree/main/skills) (`mql`,
`policy-graph`). To **run** a scan on the config an agent writes:

```bash
cnspec scan terraform ./infra           -o sarif  # Terraform (HCL or plan/state)
cnspec scan docker file ./Dockerfile    -o sarif  # Dockerfile
cnspec scan k8s ./deploy.yaml           -o sarif  # Kubernetes manifest
cnspec scan cloudformation ./stack.yaml -o sarif  # CloudFormation
```

- Add `--incognito` to scan locally without a Mondoo Platform account.
- Add `-f <bundle>` (repeatable) to load a policy bundle; without a policy source, cnspec
  reports "no policies". The `secure-guard` mod ships a per-kind default mapping.
- cnspec policies carry OWASP tags (`compliance/owasp-top-10-2025`,
  `compliance/owasp-llm-top-10-2025`), so a scan doubles as an OWASP compliance check.

Install cnspec: [mondoo.com/docs/cnspec/install](https://mondoo.com/docs/cnspec/install).

## In CI

Run the same gate in a pipeline — both engines exit non-zero on findings, so they work as a
merge gate directly:

```bash
xgrep scan . --owasp --owasp-edition 2025   # SAST/SCA/secrets; non-zero on findings
cnspec scan terraform ./infra -o sarif       # IaC policy → SARIF
```

## Map to OWASP

Latest editions only; full matrices with honest coverage levels in
[`docs/owasp.md`](../../docs/owasp.md):

- **[OWASP Top 10:2025](../../docs/owasp.md#owasp-top-10-for-applications-2025)** — xgrep owns the **code**
  categories (A05 Injection, A08 Integrity, A10 Exceptional Conditions) and the **supply
  chain** (A03 via SCA/SBOM); cnspec owns the **config/IaC** categories (A01, A02, A04-config,
  A07, A09). Only **A06 Insecure Design** is out of static scope.
- **[OWASP Top 10 for LLM & GenAI 2025](../../docs/owasp.md#owasp-top-10-for-llm-and-genai-2025)** — strongest
  on **LLM02** (secrets/PII), **LLM03** (SCA/AIBOM + AI-tooling governance), **LLM05** (treat
  LLM output as untrusted). cnspec adds config coverage of LLM01/04/06/08/10.

Read the matrix row rather than assuming coverage — the cells state Strong / Partial / N/A honestly.

## If `xgrep guard` blocks an action

The guard checks prompts and tool calls before they run; when it blocks one it names the rule
and where it matched (never the value). Then:

- **Never work around it.** Don't rephrase, split, encode, or move the command into a script
  to get past the guard, and don't edit, disable, or uninstall the hook.
- **Explain and ask.** Tell the user which rule fired, why it is risky, and offer a safe
  alternative.
- **Treat a flagged secret as exposed.** Recommend rotating it and remove it from the content
  instead of retrying.
- **The allowlist is the user's call.** Only the user adds rule ids to `.xgrep/guard-allow.txt`.
