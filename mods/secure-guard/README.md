# secure-guard

A [Claude Code mod](https://code.claude.com/docs/en/plugins/mods/overview) that puts Mondoo's
scanners in the loop as an AI agent works — routing each tool call to the right engine:

- **Shell guard (xgrep)** — holds a risky Bash command behind a Proceed / Cancel pane until
  you answer. xgrep here **prevents secrets and PII from leaving** via a prompt or tool call,
  and blocks dangerous commands.
- **Inline code review (xgrep)** — after the agent writes or edits code, scans it and hands
  high-confidence findings back right after the tool result so the agent fixes them in the
  same turn. xgrep here **enforces the OWASP Top 10** (SAST taint) plus SCA and secrets on the
  code.
- **IaC policy guard (cnspec)** — after the agent writes or edits Terraform, a Dockerfile, or
  a Kubernetes / CloudFormation manifest, runs cnspec policy checks and hands violations back
  the same way. Terraform and Dockerfiles get the xgrep review too, so a hard-coded secret in
  `main.tf` is still caught.

So xgrep runs in two complementary modes — **prevent secrets/PII leaving** (guard) and
**enforce the OWASP Top 10 on code** (scan) — and cnspec adds IaC policy. This single routing
and finding logic lives in [`hooks/core.mjs`](./hooks/core.mjs), shared with the other agent
adapters; this file is the Claude Code adapter.

Inline review is **advisory** (the edit always lands); only the shell guard can hold/block.
Everything is **fail-open**: a scanner that is missing, too old, or errors never wedges your
session.

## Install

```
/plugin install secure-guard --marketplace mondoohq/secure-stack
```

That works in one step on Claude Code 2.1.275 or later. On an older version, add the
marketplace first:

```bash
claude plugin marketplace add mondoohq/secure-stack
claude plugin install secure-guard@secure-stack
```

The mod loads in your next session. Run `/secure-guard` to check it is reaching its engines.

## The two engines

- **xgrep** (shell + code) — fetched automatically from the public npm package if a
  new-enough one isn't installed. Learn more: [xgrep.ai](https://xgrep.ai) /
  [docs](https://mondoo.com/docs/xgrep).
- **cnspec** (IaC policy) — must be [installed](https://mondoo.com/docs/cnspec/install)
  (`CNSPEC_PATH` or `cnspec` on `PATH`). If it isn't, the IaC guard stays silently off.

### Where the IaC policies come from

The IaC guard works with no configuration. By default it runs the latest public
[cnspec policy bundles](https://github.com/mondoohq/cnspec/tree/main/content) that match the
file (Terraform: AWS/Azure/GCP security; Dockerfile and Kubernetes: security and best
practices; CloudFormation: AWS security). cnspec downloads them from GitHub when it scans.

**Only policies come down. Your files never go up.** cnspec evaluates the file on your machine,
runs `--incognito`, and reports results to nowhere but the agent. The first download in a
session is announced with a toast and a transcript line, so it is never silent.

Other policy sources, in precedence order:

| Set | Policies | Network |
|-----|----------|---------|
| `CNSPEC_POLICY_BUNDLE` | your bundle(s): comma-separated local paths, `https://` or `s3://` URLs | only if a URL |
| `CNSPEC_CONTENT_DIR` | the same public bundles, from a local [cnspec](https://github.com/mondoohq/cnspec) `content/` checkout | **none, fully offline** |
| `CNSPEC_USE_PLATFORM=1` | the policies assigned in your logged-in Mondoo Platform space | cnspec **reports the scan results to your space** (opt-in for that reason) |
| *(nothing)* | the latest public bundles | policies download; nothing is uploaded |

A custom bundle needs policy **filters that match the IaC platform** you're scanning
(`terraform-hcl`, `dockerfile`, `k8s`, `cloudformation`), or cnspec has nothing to run.

## Status in a session

Run `/secure-guard` to see how it's reaching each engine (xgrep: daemon / in-process /
fetched; cnspec: available / not installed).

## Testing

Pure logic (finding filters, path routing, SARIF parsing, advisory text, version checks) is
unit-tested; an end-to-end scenario drives the engines against the real binaries:

```bash
node --test hooks/*.test.mjs                 # unit tests (no binaries needed)
claude plugin test .                         # hook-level tests, run by Claude Code itself
node test/pipeline-scenario.mjs              # end-to-end (XGREP_PATH / CNSPEC_PATH to skip the download)
```

The repo's build/validate/test commands are in the root [`AGENTS.md`](../../AGENTS.md).

## License

[Apache License 2.0](./LICENSE). The xgrep and cnspec binaries it invokes are distributed
under their own terms.
