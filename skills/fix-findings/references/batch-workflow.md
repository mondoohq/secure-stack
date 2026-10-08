# Batch workflow — input modes, selection, and reporting

`fix-findings` turns a *set* of findings into verified fixes. The orchestration is:
resolve input → select → partition by tier → apply (deterministic batch, then
assisted loop) → surface advisory → report. This reference covers the parts specific
to the batch layer; the per-finding assisted mechanics live in
[remediation-loop.md](remediation-loop.md).

## One input: `findings.json` (optionally triaged)

`findings.json` is the single source of truth — each finding carries its tier
(`extra.fix_info.kind`), contract, `extra.fingerprint`, and, once reviewed, its
verdict (`extra.triage.status`). There is no separate report to parse; the verdict
lives on the finding.

```bash
xgrep scan --json <target> > findings.json   # if you don't already have it
```

- **Triaged (preferred):** findings carry `extra.triage` (written by `triage-findings`).
  Fix only confirmed true-positives: `xgrep fix apply --confirmed < findings.json`.
  `false-positive` findings are skipped automatically; `needs-review` / un-reviewed
  fall to `out-of-scope`.
- **Un-triaged:** no verdicts. Narrow by scope instead — `--rule <id,…>`,
  `--max-severity ERROR|WARNING|INFO`, `--min-confidence HIGH|MEDIUM|LOW`. (A finding
  already marked `false-positive` is still never fixed.)

To triage first, run `/triage-findings` — it writes `extra.triage` back into the same
`findings.json`, keyed by `fingerprint`.

## Piping the whole file is safe

`xgrep fix` accepts the whole `findings.json` on stdin and derives candidates only
from its **deterministic** findings; it never authors an `assisted` or `advisory`
edit on its own (those return `needs-agent` / `advisory`). So you don't pre-filter —
let `--confirmed` and the scope flags partition; excluded findings are reported
`out-of-scope`, never silently dropped.

## Work order

Reuse triage's prioritization so the most important fixes land first and a partial
run still clears the highest-risk findings:

1. **ERROR** severity, high-confidence first
2. **ERROR** severity, remaining
3. **WARNING** severity
4. **INFO** severity

Within a severity, prefer injection / auth-bypass over configuration, and systemic
(many-file) issues over one-offs.

## Consolidated report template

End every run with a summary keyed by fingerprint, mirroring `FixReport.summary`:

```
## Fix summary — <N> findings (<confirmed | all>)

Deterministic:  <applied> applied, <rejected> rejected
Assisted:       <applied> applied, <verified> verified, <needs-agent> unresolved
Advisory:       <n> surfaced (hand-fix)
Out of scope:   <n>   Stale cache: <n>

### Cleared
- <fingerprint>  <rule-id>  <path>:<line>   (deterministic | assisted)

### Not cleared
- <fingerprint>  <rule-id>  <path>:<line>   reason=<rejection-reason>  next: <step>

### Advisory worklist
- <rule-id>  <path>:<line>   <hint>
```

Report only **harness-confirmed** outcomes as fixed — the re-scan gate is what makes
a fix real. Anything you couldn't drive to `applied`/`verified` belongs in *Not
cleared* or the *Advisory worklist*, never silently dropped.
