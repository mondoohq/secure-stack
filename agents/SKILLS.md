<skills>

You have additional SKILLs documented in directories containing a "SKILL.md" file.

These skills are:
 - author-detections -> "skills/author-detections/SKILL.md"
 - fix-findings -> "skills/fix-findings/SKILL.md"
 - secure-ai-services -> "skills/secure-ai-services/SKILL.md"
 - secure-cloud -> "skills/secure-cloud/SKILL.md"
 - secure-coding -> "skills/secure-coding/SKILL.md"
 - secure-os -> "skills/secure-os/SKILL.md"
 - secure-pipeline -> "skills/secure-pipeline/SKILL.md"
 - secure-saas -> "skills/secure-saas/SKILL.md"
 - triage-findings -> "skills/triage-findings/SKILL.md"
 - understand-code -> "skills/understand-code/SKILL.md"

IMPORTANT: You MUST read the SKILL.md file whenever the description of the skills matches the user intent, or may help accomplish their task.

author-detections: `Catch a security pattern nothing else catches — author a custom, tested xgrep/Semgrep detection rule (including taint-mode dataflow rules), or port an existing rule to new languages. Use when a vulnerability or anti-pattern needs its own detection, or to extend coverage to another language.`
fix-findings: `Fix xgrep security findings and prove each fix holds — one finding or a whole set — via the verify/apply harness. Auto-applies deterministic fixes (xgrep fix --confirmed), drives the assisted author/verify/apply loop per finding, and surfaces advisory guidance, reporting a per-fingerprint summary. Use to remediate a confirmed finding, or every triage-confirmed true positive in a findings.json, after a scan or triage.`
secure-ai-services: `Secure AI services and the AI tooling in your stack — scan OpenAI, Anthropic, vLLM, Databricks AI, and vector stores with cnspec, and govern which AI agents, IDE extensions, and MCP servers are approved (mondoo-ai-security, mondoo-mcp-security), mapped to the OWASP Top 10 for LLM & GenAI. Use to check an AI service's configuration or audit AI tooling on a host.`
secure-cloud: `Audit cloud account security posture — scan AWS, Azure, GCP (and Alibaba, Oracle, Cloudflare, Kubernetes) against CIS foundations and Mondoo cloud policies with cnspec, finding IAM, network, storage, encryption, and service misconfigurations mapped to compliance. Use to check a cloud account, subscription, project, or cluster's posture.`
secure-coding: `Review code for security vulnerabilities and provide secure coding guidance across Go, Python, JavaScript, Java, Ruby, C#, and Swift, aligned to OWASP Top 10:2025 (application) and aware of the OWASP Top 10 for LLM & GenAI 2025. Triggers on code review, security questions, and vulnerability prevention.`
secure-os: `Audit and harden operating systems and network devices — scan a Linux, macOS, or Windows host (or a container image, or network gear like Cisco/Arista/Fortinet/Juniper/PAN-OS) against CIS and vendor benchmarks with cnspec, surfacing misconfigurations and vulnerable packages mapped to compliance. Use to check a server, workstation, image, or device's security posture.`
secure-pipeline: `Verify and enforce security before code ships — scan code (SAST/SCA/secrets) with xgrep and infrastructure/config (Terraform, Dockerfile, Kubernetes, CloudFormation) with cnspec, then triage and fix findings, mapped to OWASP Top 10:2025 and the OWASP Top 10 for LLM & GenAI 2025. Use to gate a change, wire a CI check, or run a pre-merge/pre-ship security pass across code, dependencies, secrets, and IaC.`
secure-saas: `Audit SaaS and identity-provider security posture — scan GitHub, GitLab, Okta, Google Workspace, Microsoft 365, Slack, Atlassian, and Snowflake with cnspec for access, MFA, sharing, and configuration risks, mapped to compliance. Use to check a SaaS tenant, org, or identity provider's settings.`
triage-findings: `Decide whether a security finding is real — classify xgrep scan results as true or false positives by tracing dataflow from source to sink and mapping call chains with the code graph. Use to triage SAST findings before fixing, cut false positives, or confirm a vulnerability is exploitable.`
understand-code: `Understand an unfamiliar codebase before you change it — map structure, find where symbols are defined and used, trace call chains, and assess a change's blast radius, using xgrep's AST code graph and fast text search. Use before editing unfamiliar code, locating a definition or caller, or judging what a change might break.`

Paths referenced within SKILL.md files are relative to that skill's directory.

</skills>

## If `xgrep guard` blocks an action

The xgrep guard hook checks prompts and tool calls before they run. When it blocks one,
it names the rule and where it matched (never the value). Then:

- **Never work around it.** Don't rephrase, split, encode or move the command into a
  script to get past the guard, and don't edit, disable or uninstall the hook.
- **Explain and ask.** Tell the user which rule fired, why it is risky, and offer a
  safe alternative.
- **Treat a flagged secret as exposed.** Recommend rotating it and remove it from the
  content instead of retrying.
- **The allowlist is the user's call.** Only the user adds rule ids to
  `.xgrep/guard-allow.txt`.
