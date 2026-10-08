# secure-ai-services

Secure AI services and the AI tooling in your stack by invoking [cnspec](https://github.com/mondoohq/cnspec):
scan OpenAI, Anthropic, vLLM, Databricks AI, and vector stores, and govern which AI agents, IDE
extensions, and MCP servers are approved — mapped to the OWASP Top 10 for LLM & GenAI.

The posture pillar for **AI** — a sibling of `secure-os`, `secure-cloud`, and `secure-saas`. For
the *code* side of LLM security (insecure output handling, secrets in prompts), use
`secure-pipeline` / `secure-coding`.

See [SKILL.md](./SKILL.md) for the scan commands, the bundles cnspec runs, and the OWASP LLM
mapping. Requires `cnspec` ([install](https://mondoo.com/docs/cnspec/install)) plus access to the
target service or host.

## License

[Apache-2.0](../../LICENSE).
