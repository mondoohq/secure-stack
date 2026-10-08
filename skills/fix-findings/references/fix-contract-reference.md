# Fix-info & fix-contract reference

Every fixable finding in `xgrep scan --json` carries `extra.fix_info`.
It tells you who authors the edit and, for assisted findings, exactly what a valid
fix must achieve.

## `extra.fix_info`

```jsonc
{
  "kind": "deterministic | assisted | advisory",
  "edits": [                       // present for deterministic fixes
    {
      "start_byte": 420,           // span to replace (half-open [start,end))
      "end_byte": 480,
      "replacement": "…",
      "start_line": 18,            // output-only 1-based position of the span,
      "start_column": 5,           //   so renderers (SARIF/LSP) can place the edit
      "end_line": 18,
      "end_column": 41
    }
  ],
  "hint": "…",                     // natural-language guidance (the rule's fix-hint)
  "contract": { … }                // present for assisted fixes (see below)
}
```

- **`kind`** decides the workflow:
  - `deterministic` — apply `edits` directly via `xgrep scan --json … | xgrep fix
    apply` (no authoring). An insertion is the degenerate `start_byte == end_byte`.
  - `assisted` — you author the edit from `contract`; xgrep verifies it.
  - `advisory` — `hint` only; fix by hand (e.g. rotate a secret).

## `extra.fix_info.contract` (assisted only)

```jsonc
{
  "unsafe_region": {
    "start_byte": 380,
    "end_byte": 520,
    "start_line": 16,
    "end_line": 20,
    "function": "getUser"          // enclosing function, when known
  },
  "strategy": "Use a parameterized query with ? placeholders…",
  "acceptance_criteria": [
    "the patched file still parses",
    "the py-sql-injection finding no longer fires on the changed lines",
    "no new equal-or-higher-severity finding appears in the region"
  ]
}
```

- **`unsafe_region`** — the span you must change, and its enclosing function. Your
  edits should fall within (or tightly around) this region.
- **`strategy`** — the natural-language approach (the rule's fix-hint).
- **`acceptance_criteria`** — the mechanical checks the verify/apply harness will
  enforce on your candidate. Satisfy these and the candidate is accepted.

## Supporting evidence on the same result

- `dataflow_trace.taint_source` / `.sink` / `.steps` — where untrusted data enters,
  where it causes harm, and the path between (for taint findings).
- `context.before` / `.after` — surrounding source lines.
- `context.function` / `.callers` / `.callees` — call-graph location.

## The candidate you submit

A candidate is the inverse shape — byte-span replacements you author:

```jsonc
{
  "path": "src/db.py",
  "rule_id": "py-sql-injection",   // the finding the edit must clear
  "edits": [
    { "start_byte": 420, "end_byte": 480, "replacement": "…" }
  ]
}
```

You supply only byte offsets and replacement text; the line/column fields are
output-only and not needed on input.

## The verdict you get back

```jsonc
{
  "accepted": true,
  "applied": false,                // true only after `fix apply` (verify never writes)
  "reason": "",                    // set when accepted is false (see remediation-loop.md)
  "diff": "--- a/…\n+++ b/…\n…"     // unified-diff preview of the edit
}
```
