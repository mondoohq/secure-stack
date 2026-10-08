---
name: triage-findings
description: Decide whether a security finding is real — classify xgrep scan results as true or false positives by tracing dataflow from source to sink and mapping call chains with the code graph. Use to triage SAST findings before fixing, cut false positives, or confirm a vulnerability is exploitable.
allowed-tools: Bash Read Glob Grep
---

# Triage Findings

Decide whether each xgrep scan finding is real: build context with the code graph, trace
dataflow from source to sink, check for validation/sanitization, and classify with evidence —
so only genuine, exploitable issues move on to a fix.

## When to Use

- Triaging scan findings from xgrep
- Investigating whether a finding is a true or false positive
- Understanding dataflow paths from sources to sinks
- Mapping attack surface via call chain analysis

## When NOT to Use

- Creating or modifying detection rules (use `author-detections`)
- Running a scan without investigation (just use `xgrep scan -f rules.yaml --json target/`)

## Overview

This skill guides systematic investigation of xgrep findings. For each finding, you build context using the code graph, trace dataflow, check for validation/sanitization, and classify the result with evidence.

## Workflow

### Step 1: Scan the Target

```bash
# Uses built-in rules (600+ rules across 14 languages)
xgrep scan --json <target> > findings.json

# Or with custom rules
xgrep scan -f <rules-path> --json <target> > findings.json
```

The JSON output includes code context and remediation guidance for every finding. Parse it and group findings by:
- Severity (ERROR first)
- Rule ID (related findings together)
- File/function (use `context.function` for grouping)

Present a summary: N findings across M rules, severity breakdown.

Key fields per finding:
- `extra.severity`, `extra.message`, `extra.lines` — what was found
- `context.before`/`context.after` — surrounding code for understanding
- `context.function`, `context.callers`, `context.callees` — call graph location
- `remediation.description` — how to fix it
- `remediation.has_autofix` — whether autofix is available via `extra.fix`

### Step 2: Investigate Each Finding

Note: The code graph is built automatically during the scan — every finding already includes `context.function`, `context.callers`, and `context.callees`. No separate `xgrep graph build` needed.

For each finding, starting with the highest severity:

**Start with the built-in context** — every finding already includes `context.before`/`context.after` (surrounding code), `context.function` (enclosing function), and `context.callers`/`context.callees` (immediate call graph). This is often enough for initial triage.

**For deeper investigation, use graph commands:**

```bash
# Full function context with N-hop neighborhood and inlined source
xgrep graph context <function-name> --depth 2

# Trace data path from entry point to dangerous sink
xgrep graph paths <entry-point> <dangerous-sink>

# Find all entry points for auth/access control findings
xgrep graph callers <handler-function>

# Map blast radius for data exposure findings
xgrep graph reachable <data-source-function>
```

### Step 3: Classify

Based on the evidence from Step 3:

**True Positive:**
- Untrusted data reaches a dangerous sink without adequate validation
- No sanitization on any code path between source and sink
- The sink is security-sensitive in context

**False Positive:**
- Input is validated/sanitized before reaching the sink
- The code path is unreachable from untrusted input
- The sink is not security-sensitive in this context
- Framework-level protection handles this case

**Needs Review:**
- Partial validation exists but may be incomplete or bypassable
- Complex control flow makes it hard to determine safety
- Framework-level protection may or may not apply

Always cite specific functions and line numbers as evidence.

### Step 4: Record the verdict in `findings.json`

Write the verdict **back onto each finding** as an `extra.triage` object (located by
`extra.fingerprint`), then print a short human summary. The durable record is the
JSON — one artifact carrying detection, fix capability, and verdict — not the prose.

```jsonc
"extra": {
  "...": "...",
  "fix_info": { "kind": "assisted", "...": "..." },   // xgrep's "how" (untouched)
  "triage": {                                          // your "whether"
    "reviewed": true,
    "status": "true-positive",        // | "false-positive" | "needs-review"
    "rationale": "uid flows unsanitized into execute()",
    "reviewed_by": "triage-findings",
    "reviewed_at": "<RFC3339>"
  }
}
```

Edit the JSON in place (a small `python`/`jq` step keyed on `fingerprint`), leaving
every other field intact. Then `xgrep fix apply --confirmed < findings.json` (or the
`fix-findings` skill) fixes only the `true-positive` findings and skips `false-positive`
ones automatically. See [triage-workflow.md]({baseDir}/references/triage-workflow.md)
§6 for the write-back recipe and the summary-table format. Triage decides *whether*;
xgrep already decided *how* (`extra.fix_info`).

## Investigation Patterns by Vulnerability Type

### Injection (SQL, Command, XSS) -- CWE-89, CWE-78, CWE-79

1. Identify the sink (SQL query, command execution, HTML output)
2. Trace backwards: `xgrep graph callers <sink-function>`
3. Find the entry point where user input enters
4. Check every function in the path for sanitization
5. Verify sanitization is correct for the specific context (SQL vs HTML vs shell)

### Authentication/Authorization -- CWE-287, CWE-862

1. Identify the protected resource or action
2. `xgrep graph callers <handler>` to find all entry points
3. Check if authentication middleware is applied to all paths
4. Look for alternative paths that bypass checks

### Sensitive Data Exposure -- CWE-200, CWE-532

1. Identify where sensitive data is created or loaded
2. `xgrep graph reachable <data-source>` to see where it flows
3. Check for logging, error messages, or API responses that include it
4. Verify encryption/masking before external output

## References

- Code graph commands: [graph-commands.md]({baseDir}/references/graph-commands.md)
- Detailed triage workflow: [triage-workflow.md]({baseDir}/references/triage-workflow.md)

## Tips

- Use `--depth 1` for focused context, `--depth 2` for broader investigation
- `xgrep graph context` is the most useful single command -- topology and code in one shot
- Confidence levels on edges: `certain` (direct call), `inferred` (method on known type), `uncertain` (dynamic dispatch)
- Function names can be partial matches (e.g., `EvalRule` matches `EvalRule` and `EvalRuleWithContext`)
- For exact matches, use the full node ID: `pkg/core/eval.go::EvalRule`

## Part of the secure-your-stack toolkit

Triage sits between scan and fix: `secure-pipeline` produces the findings, this skill decides
which are real, and `fix-findings` remediates the confirmed ones. The `secure-guard` mod
surfaces high-confidence findings to the agent automatically as code is written.
