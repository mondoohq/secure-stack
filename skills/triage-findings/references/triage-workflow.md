# Triage Workflow

## Full Investigation Process

### 1. Run the Scan

```bash
# Uses built-in rules by default
xgrep scan --json <target> > findings.json

# Or with custom rules
xgrep scan -f <rules-path> --json <target> > findings.json
```

Note: The code graph is built automatically during the scan. Every finding includes `context.function`, `context.callers`, and `context.callees`. No separate `xgrep graph build` needed. The `xgrep graph` subcommands are only needed for deeper investigation beyond what's in the finding JSON.

### 2. Summarize Findings

Parse the JSON output. Each finding contains:

**Core fields (Semgrep-compatible):**
- `check_id`: rule that fired
- `path`: file path
- `start` / `end`: location with `line`, `col`, and `offset` (byte offset)
- `extra.severity`: ERROR, WARNING, INFO
- `extra.message`: human-readable description
- `extra.lines`: matched source code
- `extra.fix`: computed autofix replacement (if available)
- `extra.metavars`: captured metavariable values
- `extra.metadata`: CWE, OWASP, category, confidence, etc.
- `extra.fingerprint`: stable hash for deduplication across scans
- `extra.is_ignored`: whether the finding is suppressed

**Code context (always present):**
- `context.language`: detected language
- `context.before` / `context.after`: surrounding source lines
- `context.function`: enclosing function name (from code graph)
- `context.callers` / `context.callees`: call graph neighbors

**Remediation guidance:**
- `remediation.description`: human-readable fix hint
- `remediation.has_autofix`: whether `extra.fix` can be applied automatically

Group by severity, then by rule ID.

### 3. Prioritize

Investigation order:
1. **ERROR** severity with high-confidence metadata
2. **ERROR** severity, remaining
3. **WARNING** severity
4. **INFO** severity

Within each severity, prioritize by:
- CWE risk rating (injection > information disclosure > configuration)
- Number of affected files (systemic issues first)

### 4. Investigate Each Finding

For each finding, gather evidence using graph commands:

**Step A: Get function context**
```bash
xgrep graph context <function-containing-finding> --depth 2
```

Read the output. Understand what the function does, who calls it, and what it calls.

**Step B: Trace the data path (for injection/taint findings)**
```bash
xgrep graph paths <entry-point-function> <sink-function>
```

For each function along the path, read the code and check for:
- Input validation or sanitization
- Type checking or encoding
- Framework-provided security measures

**Step C: Check all entry points (for auth/access findings)**
```bash
xgrep graph callers <protected-handler>
```

Verify that every caller goes through authentication/authorization middleware.

**Step D: Map data exposure (for sensitive data findings)**
```bash
xgrep graph reachable <data-source-function>
```

Check all reachable functions for logging, error messages, or API responses.

### 5. Classify

| Classification | Criteria |
|---------------|----------|
| **True Positive** | Untrusted data reaches sink, no adequate sanitization on any path, sink is security-sensitive |
| **False Positive** | Validation exists and is sufficient, OR path is unreachable from untrusted input, OR sink is not dangerous in context |
| **Needs Review** | Partial validation (may be incomplete or bypassable), complex control flow, framework protection that may not apply |

**Always cite evidence**: specific function names, file paths, and line numbers.

### 6. Record the verdict — write it back into `findings.json`

Don't end at prose. Write each verdict **back onto the finding** in the
`findings.json` you scanned, as an `extra.triage` object. That single artifact then
carries detection + fix capability + your verdict, and `xgrep fix` consumes it
directly — no markdown to parse.

For each finding, set `extra.triage` (locate the finding by `extra.fingerprint`):

```jsonc
"triage": {
  "reviewed": true,
  "status": "true-positive",          // | "false-positive" | "needs-review"
  "rationale": "uid from request.args flows unsanitized into cursor.execute()",
  "reviewed_by": "triage-findings",
  "reviewed_at": "<RFC3339 timestamp>"
}
```

- `status` is your classification, lowercase-hyphenated:
  `true-positive` / `false-positive` / `needs-review`.
- `rationale` is the one-line evidence (source → sink, why reachable or why not).
- Edit the JSON in place (e.g. with a small `python`/`jq` step keyed on
  `fingerprint`); leave every other field untouched so `fix_info`, `fingerprint`,
  and offsets still line up.

Then **print a short human summary** to the chat — a table is enough; the durable
record is the JSON, not the prose:

| Rule | Location | Verdict | Fix tier | Why |
|------|----------|---------|----------|-----|
| `python-sql-injection` | `db.py:5` | true-positive | assisted | `uid` → `execute()` unsanitized |
| `python-cookie-no-httponly` | `views.py:3` | false-positive | deterministic | non-sensitive UI cookie |

This is the hand-off to fixing: `xgrep fix apply --confirmed < findings.json` (or the
`fix-findings` skill) then fixes only the `true-positive` findings, **skips**
`false-positive` ones automatically, and never has to read a report. Triage decides
*whether*; xgrep already decided *how* (`extra.fix_info`).

## Investigation Patterns by Vulnerability Type

### Injection (CWE-89, CWE-78, CWE-79)

1. Identify the sink (SQL query, command execution, HTML output)
2. Trace backwards: `xgrep graph callers <sink-function>`
3. Find the entry point where user input enters
4. Check every function in the path for sanitization
5. Verify sanitization is correct for the specific context:
   - SQL: parameterized queries, not string escaping
   - Shell: argument arrays, not shell escaping
   - HTML: context-aware encoding, not blanket escaping

### Authentication/Authorization (CWE-287, CWE-862)

1. Identify the protected resource or action
2. `xgrep graph callers <handler>` to find all entry points
3. Check if auth middleware is applied to **all** paths, not just some
4. Look for alternative paths: direct function calls, API aliases, debug endpoints

### Sensitive Data Exposure (CWE-200, CWE-532)

1. Identify where sensitive data is created or loaded
2. `xgrep graph reachable <data-source>` to see where it flows
3. Check for:
   - Logging calls that include sensitive data
   - Error messages that leak internal state
   - API responses that include more data than needed
4. Verify encryption/masking before any external output

### Insecure Configuration (CWE-16)

1. Read the configuration or initialization code
2. Check if insecure defaults are overridden in production
3. Look for environment-specific configuration that may differ
4. Verify the finding applies to production, not just development

### Cryptographic Issues (CWE-327, CWE-328)

1. Identify the cryptographic operation (hashing, encryption, signing)
2. Check the algorithm used (MD5/SHA1 for security = bad, for checksums = ok)
3. Check key/IV generation (hardcoded = bad, derived from secure random = ok)
4. Context matters: a weak hash for cache keys is not the same as for passwords
