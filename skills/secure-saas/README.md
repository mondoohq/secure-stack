# secure-saas

Audit SaaS and identity-provider security posture by invoking [cnspec](https://github.com/mondoohq/cnspec):
scan GitHub, GitLab, Okta, Google Workspace, Microsoft 365, Slack, Atlassian, and Snowflake for
access, MFA, sharing, and configuration risks, mapped to compliance.

The posture pillar for **SaaS & identity** — a sibling of `secure-os`, `secure-cloud`, and
`secure-ai-services`.

See [SKILL.md](./SKILL.md) for the scan commands, the bundles cnspec runs, and the compliance
mapping. Requires `cnspec` ([install](https://mondoo.com/docs/cnspec/install)) plus API
credentials for the target SaaS.

## License

[Apache-2.0](../../LICENSE).
