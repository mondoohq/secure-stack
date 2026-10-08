---
name: secure-ai-services
description: Scan AI services (OpenAI/Anthropic/vLLM/Databricks/vector stores) and govern AI tooling (agents/MCP) with cnspec
argument-hint: "<service to scan, or 'tooling' to audit approved agents/MCP on this host>"
allowed-tools: Bash Read
---

# Secure AI services / tooling

**Target:** $ARGUMENTS

Run cnspec and report the AI-security posture, mapped to the OWASP LLM Top 10.

1. Pick the scope:
   - **AI tooling on this host** (approved agents / IDE extensions / MCP servers):
     ```bash
     cnspec scan local --incognito -f mondoo-ai-security.mql.yaml  -o sarif
     cnspec scan local --incognito -f mondoo-mcp-security.mql.yaml -o sarif
     ```
   - **An AI service / vector store** (OpenAI, Anthropic, vLLM, Databricks, Weaviate): load the
     matching bundle and connect per the cnspec provider docs.
2. Summarize failures by severity, note the OWASP LLM category each maps to (strongest on
   LLM02/03/06), and give the remediation. Invoke the `secure-ai-services` skill for the full
   workflow and bundle list.
