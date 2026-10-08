# secure-pipeline

The verify-and-enforce skill: once code is written, prove it is safe before it ships. It scans
**code** with `xgrep` (SAST / SCA / secrets) and **IaC/config** with `cnspec` (Terraform,
Dockerfile, Kubernetes, CloudFormation), then routes findings to triage (`triage-findings`) and
fixes (`fix-findings`), and maps the result to OWASP Top 10:2025 and the OWASP
Top 10 for LLM & GenAI 2025. Use it to gate a change, wire a CI check, or run a pre-merge pass.

Its companion is `secure-coding`, which helps **write** code safely in the first place; this
skill is the **scan → gate → fix** half.

See [SKILL.md](./SKILL.md) for the stage-by-stage pipeline, the scan commands for both engines,
the CI usage, and the OWASP mapping. The coverage matrices live in [`docs/owasp.md`](../../docs/owasp.md).

## License

[Apache-2.0](../../LICENSE).
