# fix-findings

A skill for fixing xgrep security findings and proving each fix holds — **one finding or a
whole set** — driven by the verify/apply harness, optionally from a `findings.json` that
`triage-findings` has reviewed.

## What it does

- Fixes a **single** confirmed finding via the per-finding verify → apply loop, **or** a
  **whole set** from a scan `findings.json` (optionally triaged, carrying `extra.triage`)
- **Fixes only triage-confirmed true-positives** with `xgrep fix --confirmed`; findings
  reviewed `false-positive` are skipped automatically
- **Auto-applies** every `deterministic` fix through the harness in one batch
- **Drives the assisted loop** for each `assisted` finding (author a byte-span edit, verify
  it, iterate on the rejection reason, apply it)
- **Surfaces advisory** guidance (e.g. rotate a leaked secret) as hand-fix items
- Reports a consolidated, per-fingerprint summary; never reports a fix without a green re-scan

## How it relates to the other skills

`secure-pipeline` scans and produces findings; `triage-findings` decides *which* are real and
writes its verdict back into the `findings.json` (`extra.triage`); **`fix-findings`** then
remediates — one finding or the confirmed set.

| Skill | Scope |
|-------|-------|
| `secure-pipeline` | Scan code + IaC; produce findings |
| `triage-findings` | Decide whether findings are real; write `extra.triage` back |
| **`fix-findings`** | Fix one finding, or a set / the triage-confirmed true positives |

## Usage

```
# Fix everything fixable in a scan (un-triaged)
/fix-findings findings.json

# Fix only the triage-confirmed true positives (findings carry extra.triage)
/fix-findings findings.json   # the skill uses `xgrep fix --confirmed`

# Custom rule pack (propagated to every scan/verify/apply)
/fix-findings findings.json --rules security-rules/
```

## Installation

```bash
claude skill install ./skills/fix-findings
```

## Prerequisites

- `xgrep` CLI must be installed and available in PATH
- Target files must be writable for `fix apply`

## The harness

Every edit — deterministic or agent-authored — passes the same gates before it is written:

1. **Parse-clean** — the patched file must still parse.
2. **Re-scan** — the targeted finding must clear, with no new equal-or-higher finding in the
   region touched.
3. **Atomic write** — a temp file is renamed over the target; no partial-write window.

The same operations are available over MCP as `fix_verify` / `fix_apply`.
