# secure-guard

A [Claude Code mod](https://code.claude.com/docs/en/plugins/mods/overview) that puts Mondoo's
scanners in the loop as an AI agent works — routing each tool call to the right engine:

- **Shell guard (xgrep)** — holds a risky Bash command behind a Proceed / Cancel pane until
  you answer. xgrep here **prevents secrets and PII from leaving** via a prompt or tool call,
  and blocks dangerous commands.
- **Inline code review (xgrep)** — after the agent writes or edits code, scans it and hands
  high-confidence findings back as the tool result so the agent fixes them in the same turn.
  xgrep here **enforces the OWASP Top 10** (SAST taint) plus SCA and secrets on the code.
- **IaC policy guard (cnspec)** — after the agent writes Terraform, a Dockerfile, or a
  Kubernetes / CloudFormation manifest, runs cnspec policy checks and hands violations back
  the same way.

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

### cnspec needs a policy source

cnspec runs the policies assigned by a logged-in Mondoo Platform, **or** a local/URL policy
bundle. To use bundles without an account, point the guard at one:

```bash
# a local bundle, an s3:// URI, or a public https:// URL (e.g. a cnspec content bundle)
export CNSPEC_POLICY_BUNDLE=/path/to/policy.mql.yaml
```

Pick a bundle whose policy **filters match the IaC platform** you're scanning
(`terraform-hcl`, `dockerfile`, `k8s`, `cloudformation`). With no policy source, cnspec
reports "no policies" and the IaC guard stays quiet.

> Status: the per-IaC-type default bundle mapping (so the IaC guard works out of the box with
> no configuration) is being finalized; today set `CNSPEC_POLICY_BUNDLE` or log in to Mondoo.

## Status in a session

Run `/secure-guard` to see how it's reaching each engine (xgrep: daemon / in-process /
fetched; cnspec: available / not installed).

## Testing

Pure logic (finding filters, path routing, SARIF parsing, advisory text, version checks) is
unit-tested; an end-to-end scenario drives the engines against the real binaries:

```bash
node --test hooks/*.test.mjs                 # unit tests (no binaries needed)
node test/pipeline-scenario.mjs              # end-to-end (XGREP_PATH / CNSPEC_PATH to skip the download)
```

The repo's build/validate/test commands are in the root [`AGENTS.md`](../../AGENTS.md).

## License

[Apache License 2.0](./LICENSE). The xgrep and cnspec binaries it invokes are distributed
under their own terms.
