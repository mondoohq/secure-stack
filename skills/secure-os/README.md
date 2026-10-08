# secure-os

Audit and harden operating systems and network devices by invoking [cnspec](https://github.com/mondoohq/cnspec):
scan a Linux/macOS/Windows host, a container image, or network gear (Cisco, Arista, FortiOS,
Junos, PAN-OS) against CIS and vendor benchmarks, with findings mapped to compliance.

The posture pillar for **hosts & devices** — a sibling of `secure-cloud`, `secure-saas`, and
`secure-ai-services`. For the *code/IaC* you deploy onto a host, use `secure-pipeline`.

See [SKILL.md](./SKILL.md) for the scan commands, the bundles cnspec runs, and the compliance
mapping. Requires `cnspec` ([install](https://mondoo.com/docs/cnspec/install)) plus access to the
target.

## License

[Apache-2.0](../../LICENSE).
