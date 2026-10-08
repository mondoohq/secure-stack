# Outcome schema, fingerprint join & NDJSON streaming

`xgrep fix verify|apply` reports one `FixOutcome` per finding/candidate. The batch
layer joins those outcomes back to the input findings by `fingerprint` and tallies
them for the summary.

## FixOutcome

```jsonc
{
  "fingerprint": "7a2f…",   // correlates to the scan finding's extra.fingerprint
  "rule_id":     "py-sql-injection",
  "path":        "src/db.py",
  "paths":       ["src/db.py", "src/utils.py"],  // cross-file changesets only
  "kind":        "deterministic",                // deterministic | assisted | advisory
  "status":      "applied",
  "reason":      "",          // rejection reason (closed vocabulary) when not cleared
  "detail":      "",          // human elaboration
  "severity":    "ERROR",
  "diff":        "--- src/db.py\n+++ src/db.py\n@@ …",
  "attempt":     1            // your 1-based try number, echoed back
}
```

### FixStatus (closed vocabulary)

| status | meaning |
|---|---|
| `applied` | Edit verified and written atomically (`fix apply`). |
| `verified` | Passed the harness but not written (`fix verify`). |
| `rejected` | Harness rejected the edit — see `reason`. |
| `needs-agent` | An `assisted` finding with no edit authored yet — drive the loop. |
| `advisory` | Advisory-only; no code edit. Surface the hint. |
| `out-of-scope` | Excluded by a scope filter (`--rule` / `--max-severity` / `--min-confidence`). |
| `stale-cache` | The cached finding's file changed since the scan — re-scan and retry. |

### Rejection `reason` (closed vocabulary)

| reason | next move |
|---|---|
| `span-conflict` | Edits overlap or a span is out of range — recompute offsets from the current file, make spans disjoint. |
| `parse-error` | Patched file no longer parses — fix `replacement` syntax. |
| `finding-not-cleared` | Target rule still fires — actually remove the vulnerable pattern. |
| `new-finding-introduced` | A new equal/higher-severity finding appeared — inspect the `diff`, choose a non-trading fix. |
| `no-change` | Edit nets to nothing — re-derive the span / ensure `replacement` differs. |
| `read-error` | File read/write failed — check the path and permissions. |
| `rescan-error` | The re-scan gate itself failed — usually transient; retry. |

## FixReport (non-streaming)

Without `--batch`, `fix` emits one `FixReport`:

```jsonc
{
  "summary":  { "applied": 5, "needs-agent": 2, "advisory": 1, "out-of-scope": 0 },
  "outcomes": [ /* FixOutcome… */ ]
}
```

Use `summary` directly for the run tally; iterate `outcomes` for the per-finding
Cleared / Not-cleared lists.

## Candidate shapes you author (assisted tier)

Single-file edit:

```jsonc
{ "path": "src/db.py", "rule_id": "py-sql-injection",
  "edits": [ { "start_byte": 420, "end_byte": 480, "replacement": "…" } ],
  "id": "finding-7a2f", "attempt": 1 }
```

Cross-file changeset (all files verified and written as a unit, or none):

```jsonc
{ "id": "changeset-1", "rule_id": "py-sql-injection", "files": [
  { "path": "src/db.py",    "edits": [ { "start_byte": 420, "end_byte": 480, "replacement": "…" } ] },
  { "path": "src/utils.py", "edits": [ { "start_byte": 0,   "end_byte": 0,   "replacement": "from sanitize import clean\n" } ] }
] }
```

`FixEdit` byte spans are absolute and zero-width spans (`start_byte == end_byte`) are
insertions. xgrep fills `start_line`/`end_line` back on output.

## NDJSON streaming (`--batch`)

To author many candidates at once, stream newline-delimited candidates into
`fix apply --batch`; xgrep streams one `FixOutcome` line per candidate as it
completes:

```bash
cat <<'EOF' | xgrep fix apply --batch
{"id":"f1","rule_id":"py-cookie","path":"src/a.py","edits":[{"start_byte":10,"end_byte":20,"replacement":"True"}]}
{"id":"f2","rule_id":"py-cookie","path":"src/b.py","edits":[{"start_byte":30,"end_byte":40,"replacement":"True"}]}
EOF
```

Join each output line back to your input by `id` (and the finding by `fingerprint`).

## Where the deterministic candidates come from

You don't author deterministic edits — pipe the scan report and `fix` derives them
from `extra.fix_info.edits`. Pipe candidates/changesets only for the `assisted` tier.
A single `fix apply` invocation accepts a scan report, a candidate, a changeset, or
(with `--batch`) an NDJSON candidate stream — but one shape per invocation.

See [remediation-loop.md](remediation-loop.md) for the per-finding loop and
[fix-contract-reference.md](fix-contract-reference.md) for the `fix_info` / contract schema.
