# Remediation loop & rejection-reason playbook

The assisted loop is a closed cycle: author → `fix verify` → adjust → repeat →
`fix apply`. xgrep never writes an edit it has not verified, so you can iterate
freely without risk to the file (`fix verify` never writes; `fix apply` writes
only the accepted edit).

## The loop

Built-in rules are the default — no `-f`. Add `-f <rules-path>` to every command
below only when the finding came from a custom rule pack.

```bash
# 1. Scan the file holding the finding, with context.
xgrep scan --json --context 3 src/db.py > /tmp/f.json

# 2. Read /tmp/f.json → extra.fix_info.contract (unsafe_region, strategy,
#    acceptance_criteria) and the dataflow_trace / context evidence.

# 3. Author edits over the file and verify (never writes):
echo '{"path":"src/db.py","rule_id":"py-sql-injection","edits":[
  {"start_byte":420,"end_byte":480,"replacement":"cur.execute(\"… WHERE id=%s\", (uid,))"}
]}' | xgrep fix verify

# 4. If rejected, adjust per the reason (below) and re-verify.

# 5. When accepted, apply (fix apply always writes the accepted edit):
echo '{…candidate…}' | xgrep fix apply

# 6. Re-scan to confirm the finding cleared.
xgrep scan --json src/db.py
```

## Rejection-reason playbook

When `accepted` is false, `reason` tells you exactly what failed:

| `reason` | What it means | Next move |
|---|---|---|
| `span-conflict` | Two of your edits overlap, or a span is out of range / malformed. | Recompute byte offsets from the current file; make spans disjoint. Re-read the file — offsets shift after any prior apply. |
| `parse-error` | The patched file would no longer parse. | Fix the syntax of `replacement` (brackets, quotes, indentation). Verify the snippet compiles in isolation first. |
| `finding-not-cleared` | The file parses but the targeted rule still fires on a changed line. | Your edit did not remove the vulnerable pattern. Widen or correct it so the sink no longer matches (e.g. actually parameterize the query, not just reformat it). |
| `new-finding-introduced` | The edit cleared the target but introduced an equal-or-higher-severity finding on a changed line. | Inspect the new finding in the `diff`; choose a fix that does not trade one bug for another. |
| `no-change` | The edit nets to no change (e.g. replacement equals the original text, or an out-of-range span). | Re-derive the span; ensure `replacement` actually differs from the spanned bytes. |

## Practical tips

- **Re-read offsets after every apply.** Byte offsets are absolute; once a write
  lands, every later offset in the file shifts. Re-scan to get fresh spans.
- **Keep edits tight.** The smallest span that satisfies the
  `acceptance_criteria` is least likely to hit `span-conflict` or
  `new-finding-introduced`.
- **Verify before apply, always.** `fix verify` is read-only and returns the same
  verdict `fix apply` will — use it to iterate, then `fix apply` once to commit.
- **Gate in CI.** `xgrep scan --json <target> | xgrep fix apply --strict` exits
  non-zero if any fix is rejected, so a pipeline can fail loudly instead of
  silently skipping. (`fix verify --strict` gates without writing.)
- **MCP equivalents:** `fix_verify` (read-only) and `fix_apply` (writes the
  accepted edit) run the identical harness.
