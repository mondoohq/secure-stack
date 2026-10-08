---
name: fix-findings
description: Fix xgrep findings — one finding or a whole set (or the triage-confirmed true positives) — via the verify/apply harness
argument-hint: "<findings.json | finding> [--rules <rules-path>]"
allowed-tools: Bash Read Glob Grep
---

# Fix findings

**Input:** $ARGUMENTS — a scan `findings.json` (optionally triaged: findings carry
`extra.triage`), optionally a custom rule pack.

Remediate the whole set in one pass: auto-apply deterministic fixes, drive the
assisted loop for the rest, surface advisory guidance, and report what cleared.

Commands use xgrep's **built-in rules** by default — no `-f` needed. If the findings
came from a **custom** rule pack, add `-f <rules-path>` to every `scan` /
`fix verify` / `fix apply` command below.

1. **Resolve the input** — one artifact, the `findings.json`:
   - **Triaged** (findings carry `extra.triage`, written by `/triage-findings`) → fix
     only confirmed true-positives with `--confirmed`; false-positives are skipped
     automatically. If it isn't triaged yet, run `/triage-findings` first.
   - **Un-triaged** → fix every in-scope finding (narrow with `--rule` /
     `--max-severity` / `--min-confidence`). No `findings.json` yet?
     `xgrep scan --json <target> > findings.json`.

2. **Partition by tier** (`extra.fix_info.kind`) into deterministic / assisted /
   advisory and **present the plan** (counts per tier × severity) before mutating.

3. **Deterministic — auto-apply in one batch.** Pipe the whole `findings.json`; let
   `--confirmed` (and scope flags) partition it through the harness:
   ```bash
   xgrep fix apply --confirmed < findings.json   # verified + atomic; --strict to fail loud
   ```

4. **Assisted — drive the loop per finding.** Read `extra.fix_info.contract`, author
   byte-span edits, `xgrep fix verify`, iterate on `reason`, `xgrep fix apply`. Use
   `--batch` NDJSON to author several at once. (The skill's `references/remediation-loop.md`
   has the full per-finding loop and rejection-reason playbook.)

5. **Advisory — surface, don't auto-edit.** Emit `extra.fix_info.hint` as a hand-fix
   action item.

6. **Report** a consolidated, per-fingerprint summary: applied / verified / rejected
   / advisory / out-of-scope, with the rejection `reason` for anything not cleared.
   Never report a finding fixed without a clean re-scan.

Invoke the `fix-findings` skill for the full orchestration workflow, the `--confirmed`
triage flow, and the outcome schema.
