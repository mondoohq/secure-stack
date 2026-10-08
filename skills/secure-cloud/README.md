# secure-cloud

Audit cloud account security posture by invoking [cnspec](https://github.com/mondoohq/cnspec):
scan AWS, Azure, GCP, and Kubernetes (and more) against CIS foundations and Mondoo cloud
policies, finding IAM, network, storage, encryption, and logging misconfigurations mapped to
compliance.

The posture pillar for **cloud accounts** — a sibling of `secure-os`, `secure-saas`, and
`secure-ai-services`. For the Terraform/CloudFormation you deploy, use `secure-pipeline`.

See [SKILL.md](./SKILL.md) for the scan commands, the bundles cnspec runs, and the compliance
mapping. Requires `cnspec` ([install](https://mondoo.com/docs/cnspec/install)) plus credentials
for the target cloud.

## License

[Apache-2.0](../../LICENSE).
