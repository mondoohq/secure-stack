# OWASP coverage

This hub is measured against two OWASP standards, latest editions only:

- **[OWASP Top 10:2025](https://top10.owasp.org/2025/)** — application security risks in the
  code an agent writes. → [coverage matrix](#owasp-top-10-for-applications-2025)
- **[OWASP Top 10 for LLM & GenAI Applications — 2025](https://genai.owasp.org/llm-top-10/)**
  — risks in the LLM/GenAI apps an agent builds. → [coverage matrix](#owasp-top-10-for-llm-and-genai-2025)

Each matrix maps every category to how this hub helps an AI coding agent address it, using:

- **xgrep** — SAST (taint, ~38 languages), SCA (dependency vulnerabilities, 12+ ecosystems),
  and secrets, plus **bill-of-materials** generation: SBOM, **CBOM** (cryptographic), and
  **AIBOM** (AI/ML components) in CycloneDX/SPDX. Learn more at [xgrep.ai](https://xgrep.ai) /
  [docs](https://mondoo.com/docs/xgrep). xgrep reports its own OWASP Top 10 coverage with
  `xgrep scan --owasp --owasp-edition 2025`.
- **cnspec** — policy-as-code: 89 policy bundles for configuration and IaC (Terraform,
  CloudFormation, Dockerfile, Kubernetes), cloud posture, databases, SaaS, network gear, and
  a dedicated AI/LLM set — each check mapped to OWASP (app + LLM Top 10 2025), plus NIST, CIS,
  SOC 2, PCI-DSS, ISO 27001, HIPAA, and more. Open source:
  [github.com/mondoohq/cnspec](https://github.com/mondoohq/cnspec).
- **skills** — the instruction packs in this repo that teach an agent to use the tools well
  (understand-code, author-detections, triage-findings, fix-findings, secure-coding).
- **mods** — the runtime guardrails in this repo that scan an agent's tool calls and feed
  findings back before they land.

## How to read the matrices

Each row is one OWASP category. A cell says which layer addresses it and how, with honest
boundaries:

- **Strong** — a core capability detects or prevents this class directly.
- **Partial** — some instances are detectable by static analysis / policy; others need
  dynamic testing or design review.
- **N/A (static)** — a design, data, or model-behavior concern that static tooling cannot
  decide. We say so rather than claim false coverage — an empty, honest cell beats a noisy
  one. The `secure-coding` skill and design guidance still reduce these proactively.

## The mapping is data, not assertion

Both engines carry **machine-readable OWASP Top 10:2025 metadata**, so these matrices are
meant to be *generated* from the tools themselves (and CI-gated so they cannot silently
regress) — not maintained by hand:

- **xgrep** — each rule's `owasp:` metadata tags it with the `A0x:2025` category it detects;
  `xgrep scan --owasp --owasp-edition 2025` prints the live coverage scoreboard.
- **cnspec** — policy checks carry both `compliance/owasp-top-10-2025: owasp-top-10-2025-a0X`
  (app; 77+ bundles) and `compliance/owasp-llm-top-10-2025: owasp-llm-top-10-2025-llm0X`
  (152 checks), alongside ASVS 5, MITRE ATT&CK, NIST (incl. AI-100-1), PCI-DSS, SOC 2, ISO
  27001, HIPAA, and more. cnspec treats both OWASP lists as first-class compliance frameworks.

A generator walks xgrep's rule metadata and cnspec's policy tags to produce the grid; the
tables below are the human-readable view with the honest coverage levels layered on top.

## OWASP Top 10 for applications (2025)

Spec: **[OWASP Top 10:2025](https://top10.owasp.org/2025/)** (application security). Covers the
security of the **code *and* the IaC/configuration an AI agent writes**.

Two engines, cleanly complementary — and both carry machine-readable `A0x:2025` mappings:

- **xgrep** owns the **code** categories (injection, insecure design hints, integrity,
  exceptional conditions) and the **dependency supply chain** (SCA). Live scoreboard:
  `xgrep scan --owasp --owasp-edition 2025`.
- **cnspec** owns the **configuration / IaC / cloud** categories — its policy checks are
  tagged `compliance/owasp-top-10-2025` across 77+ bundles, heaviest on **A01 (796 checks),
  A02 (601), A04 (587), A07 (410), A09 (316)**, with A03 (147) and A08 (96). It scans the
  **Terraform, CloudFormation, Dockerfile, and Kubernetes** an agent produces.

Legend: **Strong** (code or config side directly detected/prevented) · **Partial** (some
instances static-detectable; others need dynamic testing / design review) · **N/A (static)**.

| # | Category | Level | Code (xgrep) | Config / IaC (cnspec) |
|---|----------|-------|--------------|------------------------|
| A01:2025 | Broken Access Control | **Strong (config)** / Partial (code) | flags missing/bypassable authorization patterns | **strong** — IAM, bucket/network access, RBAC in cloud/Terraform/CFN/K8s (796 mapped checks) |
| A02:2025 | Security Misconfiguration | **Strong** | config-file rules | **core strength** — Terraform/CFN/Dockerfile/K8s + cloud posture (601 checks); the **IaC guard mod** runs it as config is written |
| A03:2025 | Software Supply Chain Failures | **Strong** | **SCA** (vuln/outdated/unpinned deps as VEX, reachability-ranked) + install-cradle rules + **SBOM** | base-image & dependency-source policy (147 checks) |
| A04:2025 | Cryptographic Failures | **Strong** | weak crypto, hardcoded keys, **secrets** (166 families), + **CBOM** | TLS/crypto configuration (587 checks) |
| A05:2025 | Injection | **Strong (code)** | **taint analysis**, ~38 langs — SQL/command/code injection, XSS, path traversal, SSRF; the **inline-review guard** flags it as written | (code-level; cnspec n/a) |
| A06:2025 | Insecure Design | N/A (static) | — the `secure-coding` skill reduces it proactively | — |
| A07:2025 | Authentication Failures | **Strong (config)** / Partial (code) | hardcoded creds, weak-auth patterns, auth-token secrets | **strong** — authentication configuration in cloud/IaC/SaaS (410 checks) |
| A08:2025 | Software or Data Integrity Failures | **Strong** | insecure deserialization, untrusted-data sinks, dependency integrity | CI/CD & update-integrity configuration (96 checks) |
| A09:2025 | Security Logging & Alerting Failures | **Strong (config)** | sensitive-data exposure in errors/stack traces | **strong** — logging/audit/monitoring configuration (316 checks) |
| A10:2025 | Mishandling of Exceptional Conditions | Partial | fail-open handling, swallowed exceptions, panic/unwrap DoS, error-detail exposure | (code-level; cnspec n/a) |

**Net:** xgrep covers the code categories (A05, A08, A10) + the dependency supply chain
(A03); cnspec covers the config/IaC categories (A01, A02, A04-config, A07, A09). Only
**A06 Insecure Design** is N/A for static tooling (a design/threat-modeling concern) — the
rest of the Top 10 is addressed, each cell backed by real rule/policy metadata.

### Skills and mods, by role

- **Write it securely first** → `secure-coding` skill (A04, A05, A06, A08).
- **Catch it as it's written** → inline-review, SCA, and IaC **guard mods** (A02, A03, A04,
  A05, A08).
- **Author detections** → `author-detections`. **Triage & fix** → `triage-findings` →
  `fix-findings`. **Understand first** → `understand-code`. **Verify & enforce** → `secure-pipeline`.

## OWASP Top 10 for LLM and GenAI (2025)

Spec: **[OWASP Top 10 for LLM Applications — 2025](https://genai.owasp.org/llm-top-10/)**.
Covers the security of the **LLM/GenAI apps an agent builds** — and the AI tooling it uses.

Much of this list is runtime/model behavior that static tooling cannot decide; we say so
plainly rather than overclaim. But the coverage is larger than it first looks, because
**cnspec maps its AI/config policies to the LLM Top 10** (`compliance/owasp-llm-top-10-2025`,
152 checks across `ai-security`, `mcp-security`, `vllm-security`, `weaviate-security`,
`databricks-security`, and the cloud-provider AI services). Distribution: **LLM02 (45),
LLM03 (40), LLM06 (25), LLM04 (17), LLM01 (10), LLM05 (7), LLM08 (6), LLM10 (2)**. The
**code** side (secrets, SCA/AIBOM, insecure output handling) is xgrep.

cnspec also **governs the AI tooling itself** — `mondoo-ai-security` enforces approved AI
coding agents, IDE extensions, MCP servers, and local LLM runtimes; `mondoo-mcp-security`
checks MCP server/client security (prompt-injection/PII/malicious-URL content checks, tool
schema validation).

Legend: **Strong** / **Partial** / **N/A (static)**.

| # | Category | Level | How the hub helps |
|---|----------|-------|-------------------|
| LLM01:2025 | Prompt Injection | Partial | xgrep flags code that passes untrusted input into prompts/model calls; cnspec adds MCP/AI content checks (10). Robust defense is a runtime control. |
| LLM02:2025 | Sensitive Information Disclosure | **Strong** | xgrep **secrets + PII** (keys/creds/PII in code, prompts, config); the **guard mod** blocks secrets/PII leaving via prompts/tool calls; cnspec data-handling policy (45). |
| LLM03:2025 | Supply Chain | **Strong** | xgrep **SCA** (ML & app deps as VEX) + **AIBOM**; cnspec **governs AI tooling** (approved agents/IDE-extensions/MCP servers/local runtimes) and provider supply-chain config (40). |
| LLM04:2025 | Data and Model Poisoning | Partial | cnspec checks training/fine-tuning/embedding **pipeline configuration** (17, incl. Databricks/cloud ML). Poisoning itself is a data/ML concern, not statically decidable. |
| LLM05:2025 | Improper Output Handling | **Strong** | xgrep **taint** treats LLM output as untrusted and flags it reaching eval/exec/SQL/shell/markup sinks — insecure output handling as code; cnspec adds config checks (7). |
| LLM06:2025 | Excessive Agency | Partial | cnspec checks MCP tool/permission config and governs which agents/MCP servers are approved (25, `mcp-security` + `ai-security`). Whether agency is *appropriate* is design. |
| LLM07:2025 | System Prompt Leakage | Partial | xgrep flags code that logs/returns system prompts or embeds secrets in them. End-to-end prevention is a runtime control. |
| LLM08:2025 | Vector and Embedding Weaknesses | Partial | cnspec checks vector-store **configuration** (6, e.g. `weaviate-security`). Embedding/access-integrity design is otherwise out of static scope. |
| LLM09:2025 | Misinformation | N/A (static) | A model-behavior/output-quality concern — evaluation, grounding, human oversight. No cnspec/xgrep checks; we don't claim it. |
| LLM10:2025 | Unbounded Consumption | Partial | cnspec checks rate-limit/quota/resource config (2); xgrep flags missing-limit code; the guard blocks resource-exhausting commands. |

**Honest summary:** strongest on **LLM02, LLM03, LLM05** (code + config), with real
**partial** coverage of LLM01, LLM04, LLM06, LLM07, LLM08, LLM10 via cnspec configuration
policy and xgrep code patterns. Only **LLM09 Misinformation** has no static coverage and we
say so. The AI-tooling governance (`mondoo-ai-security`/`mondoo-mcp-security`) is the
agentic-supply-chain backbone.

---

> xgrep: [xgrep.ai](https://xgrep.ai) / [docs](https://mondoo.com/docs/xgrep). cnspec:
> [github.com/mondoohq/cnspec](https://github.com/mondoohq/cnspec).
