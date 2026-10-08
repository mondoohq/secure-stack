---
name: fix-findings
description: Fix xgrep security findings and prove each fix holds — one finding or a whole set — via the verify/apply harness. Auto-applies deterministic fixes (xgrep fix --confirmed), drives the assisted author/verify/apply loop per finding, and surfaces advisory guidance, reporting a per-fingerprint summary. Use to remediate a confirmed finding, or every triage-confirmed true positive in a findings.json, after a scan or triage.
allowed-tools: Bash Read Glob Grep
---

# Fix Findings

Remediate xgrep findings — **one or a whole set** — and **prove each fix holds** with
xgrep's verify/apply harness. For a single confirmed finding, run the per-finding loop
(Step 4) directly; for a scan or triage run, partition the findings by fix tier and drive
each tier to a verified result. xgrep owns the mechanical gates (parse-clean, re-scan,
atomic write); you own the reasoning that authors any non-mechanical edit.

## When to Use

- Fixing a **single**, already-confirmed finding (jump to Step 4 — the per-finding loop)
- Fixing **many** findings from a scan in one pass
- Fixing exactly the **triage-confirmed true positives** in a `findings.json`
  (the verdicts `triage-findings` wrote into `extra.triage`)
- Running a deterministic-fix sweep across a codebase with a verified summary

## When NOT to Use

- Deciding *whether* findings are real — that is triage. Use `triage-findings` first;
  with `--confirmed` this skill trusts the `extra.triage` true-positive verdicts.
- Suppressing/ignoring findings, or creating rules (use `author-detections`).

**Rules are built in.** Every command below uses xgrep's bundled rules by default
(600+ across 14 languages, security + secrets) — no `-f` needed. Pass `-f <rules-path>`
only when the findings came from a *custom* rule pack; then add the **same** `-f` to
every `scan` / `fix verify` / `fix apply` so the re-scan gate uses the rule that
produced the finding.

## Step 1 — Resolve the input (one artifact: `findings.json`)

The input is a scan `findings.json` (`{results:[...]}`). It is the single source of
truth: each finding carries its tier and contract (`extra.fix_info` — *how* to fix),
its `fingerprint`, and — if it has been triaged — a verdict (`extra.triage` — whether
to fix). There is no separate markdown report to parse.

Two cases, distinguished by whether the findings carry `extra.triage`:

- **Triaged input (preferred)** — findings reviewed by `triage-findings` (or a human)
  carry `extra.triage.status` (`true-positive` / `false-positive` / `needs-review`).
  Fix **only the confirmed true-positives** with `--confirmed`; `false-positive`
  findings are skipped automatically. If the file isn't triaged yet, run
  `/triage-findings` first (it writes `extra.triage` back into `findings.json`).

- **Un-triaged input** — a raw scan with no verdicts. Fix every finding, narrowed by
  scope (severity / confidence / rule) rather than by review. (Even here, any finding
  already marked `false-positive` is never fixed.)

If you don't have a `findings.json` yet:
```bash
xgrep scan --json <target> > findings.json
```

## Step 2 — Partition by tier and present the plan

Bucket the selected findings by `extra.fix_info.kind`:

- **`deterministic`** — xgrep already computed the exact edit (Step 3).
- **`assisted`** — xgrep emits a fix contract; you author the edit (Step 4).
- **`advisory`** — guidance only, no code edit (Step 5).

Show the plan before mutating anything: counts per tier × severity, and the work
order (ERROR → WARNING → INFO; within a severity, injection/auth before config). Get
a clean picture of scope first — a batch that silently skips half the findings is
worse than one that says what it will and won't touch.

## Step 3 — Deterministic: auto-apply in one batch

Pipe the **whole** `findings.json` through the harness — no need to pre-filter. With
triaged input, `--confirmed` keeps only `true-positive` findings (and always skips
`false-positive`); everything else falls to `out-of-scope`, reported not dropped:

```bash
# Triaged input: fix only the confirmed true-positives, verified + atomic.
xgrep fix apply --confirmed < findings.json

# Preview first (no writes) — same verdict fix apply will return.
xgrep fix verify --confirmed < findings.json
```

For un-triaged input, drop `--confirmed` and scope with `--rule` / `--max-severity` /
`--min-confidence` as needed. `fix` only ever auto-applies the **deterministic** tier
from a piped report — `assisted` findings come back as `needs-agent` and `advisory` as
`advisory` — so piping the whole file and letting `fix` apply just the mechanical ones
is safe. Add `--strict` to exit non-zero on any rejection (use in CI). The re-scan gate
runs by default. Collect the streamed `FixOutcome`s (keyed by fingerprint) for the report.

## Step 4 — Assisted: drive the loop per finding

`--confirmed` only governs the deterministic auto-apply batch (Step 3); for assisted
findings, **you** apply the same filter — with triaged input, author edits **only**
for findings whose `extra.triage.status == "true-positive"`, and skip
`false-positive` / `needs-review`.

For each such `assisted` finding, run the per-finding remediation loop (this is also the
whole flow when you're fixing a single finding — full playbook in the references below):

1. Read `extra.fix_info.contract`: `unsafe_region` (byte/line span + enclosing
   function), `strategy` (the fix approach), `acceptance_criteria` (what xgrep will
   verify). The evidence (`dataflow_trace`, `context`) rides on the same finding.
2. Read the file around `unsafe_region`; if you need types or flow, investigate with
   the code graph (`xgrep graph context <fn> --depth 2`, `xgrep graph paths <src> <sink>`).
3. Author byte-span replacements and verify (never writes):
   ```bash
   echo '{"path":"src/db.py","rule_id":"py-sql-injection","edits":[
     {"start_byte":420,"end_byte":480,"replacement":"cur.execute(\"… WHERE id=%s\", (uid,))"}]}' \
     | xgrep fix verify
   ```
4. If `accepted` is false, adjust per `reason` and re-verify:

   | `reason` | Next move |
   |---|---|
   | `span-conflict` | Re-read the file and recompute byte offsets (they shift after any prior apply); make spans disjoint. |
   | `parse-error` | Fix the syntax of `replacement`; verify the snippet parses in isolation. |
   | `finding-not-cleared` | The vulnerable pattern still matches — actually remove it (e.g. parameterize, don't reformat). |
   | `new-finding-introduced` | Inspect the new finding in the `diff`; pick a fix that doesn't trade one bug for another. |
   | `no-change` | Re-derive the span; ensure `replacement` differs from the spanned bytes. |

5. Apply once accepted (`fix apply` writes the accepted edit atomically):
   ```bash
   echo '{…candidate…}' | xgrep fix apply
   ```

**Re-read offsets after every apply** — byte offsets are absolute, so every later
offset in a file shifts once a write lands. Fix one finding fully (verify → apply →
confirm) before moving to the next in the same file, or author all edits for a file
against a single fresh scan. To author several candidates across files at once,
stream them as NDJSON: `xgrep fix apply --batch` (one `FixOutcome` per line).

For the full rejection-reason playbook and the fix-contract schema, see
[remediation-loop.md]({baseDir}/references/remediation-loop.md) and
[fix-contract-reference.md]({baseDir}/references/fix-contract-reference.md).

## Step 5 — Advisory: surface, don't auto-edit

For `advisory` findings, read `extra.fix_info.hint` and present it as a hand-fix
action item (e.g. *rotate the leaked secret and purge it from history* — a code edit
won't fix it). Never mark an advisory finding as fixed automatically.

## Step 6 — Report

Emit a consolidated summary keyed by fingerprint, mirroring `FixReport.summary`:

- Per tier: how many `applied` / `verified` / `rejected` / `advisory` /
  `out-of-scope` / `stale-cache`.
- For anything not cleared, the rejection `reason` and a short next step.
- A **residual worklist**: assisted findings you could not author a passing edit
  for, and every advisory item, so nothing is silently dropped.

Never report a finding fixed without a clean re-scan — the harness enforces this, and
your summary should reflect only harness-confirmed outcomes.

## Over MCP

The same operations are available as `fix_verify` (read-only) and `fix_apply` (writes
the accepted edit). Both run the identical harness, so a rejected candidate is never
written; iterate with `fix_verify`, commit with `fix_apply`.

## References

- Batch workflow, input modes & triage→findings join: [batch-workflow.md]({baseDir}/references/batch-workflow.md)
- Outcome schema, fingerprint join & NDJSON streaming: [outcome-reference.md]({baseDir}/references/outcome-reference.md)
- Per-finding remediation loop & rejection playbook: [remediation-loop.md]({baseDir}/references/remediation-loop.md)
- Fix-contract schema (unsafe_region, strategy, acceptance_criteria): [fix-contract-reference.md]({baseDir}/references/fix-contract-reference.md)

## Tips

- **Plan before you mutate.** Show the tier × severity breakdown first; a batch that
  hides what it skipped is worse than one that names it.
- **Deterministic is free — sweep it first.** One `fix apply < selected.json` clears
  the whole mechanical tier; spend your reasoning on the assisted tier.
- **Tight edits win.** The smallest span that satisfies the `acceptance_criteria` is
  least likely to hit `span-conflict` or `new-finding-introduced`.
- **Gate in CI.** `xgrep fix apply --strict < selected.json` exits non-zero if any
  fix is rejected, so a pipeline fails loudly instead of skipping silently.

## Part of the secure-your-stack toolkit

Fixing is the last step of the loop: `secure-pipeline` scans, `triage-findings` confirms
what's real, and this skill remediates — one finding or the whole confirmed set. The
`secure-guard` mod runs the scan automatically as an agent works, so findings surface
before they ever reach a fix queue.
