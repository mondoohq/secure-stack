# xgrep Rule Workflow

## Creating a New Rule

### Step 1: Analyze the Problem

Before writing anything:

1. **Identify the vulnerability or pattern**: What exactly should this rule detect? Be specific about the dangerous operation and the conditions that make it dangerous.
2. **Choose the target language(s)**: Check whether the language has tree-sitter support (full AST matching) or is regex-only. See [language-guide.md]({baseDir}/references/language-guide.md).
3. **Decide taint vs pattern matching**:
   - **Taint mode**: Data flows from untrusted input to dangerous sink (injection, XSS, path traversal)
   - **Pattern matching**: Specific syntax that is always dangerous regardless of data flow (hardcoded credentials, insecure configuration, deprecated API usage)
4. **Search for existing rules**: Check if a similar rule already exists in the codebase before writing a new one.

### Step 2: Write Tests First

Create the test source file **before** writing the rule. Source files should be
**clean code without annotations** -- test expectations are defined in Go test
files using `testutil.RunRuleTest`.

**Directory structure:**
```
rules/<lang>/lang/security/<category>/<rule-id>/
+-- <rule-id>.xgrep.yaml     # xgrep rule
+-- <rule-id>.<ext>           # Clean source file with vulnerable + safe examples
```

**Source file requirements:**
- Group vulnerable examples together (top), safe examples below
- At least 3 vulnerable patterns and 3 safe patterns
- No `# ruleid:` or `# ok:` annotations -- keep source files clean
- Use real-world patterns from CVE examples in `cve/` where possible

**Go test file** (in `test/rules/<lang>/security_test.go`):
```go
func TestPythonSqlInjection(t *testing.T) {
    dir := filepath.Join(rulesDir(), "python", "lang", "security", "injection", "sql-injection")
    testutil.RunRuleTest(t, testutil.RuleTest{
        Rule: filepath.Join(dir, "sql-injection.xgrep.yaml"),
        Cases: []testutil.TestCase{
            {
                File:        "sql-injection.py",
                ExpectMatch: []int{10, 14, 18},  // lines with vulnerable code
            },
        },
    })
}
```

**Example source file (`sql-injection.py`):**
```python
import sqlite3

def vulnerable_examples(conn, user_input):
    conn.execute("SELECT * FROM users WHERE id = " + user_input)

    query = f"DELETE FROM users WHERE name = '{user_input}'"
    conn.execute(query)

    conn.execute("UPDATE users SET name = '%s'" % user_input)

def safe_examples(conn, user_input):
    conn.execute("SELECT * FROM users WHERE id = ?", (user_input,))

    conn.execute("SELECT * FROM users WHERE id = :id", {"id": user_input})

    conn.execute("SELECT COUNT(*) FROM users")
```

**Reference material:** Check `cve/<lang>/lang/security/<category>/` for real-world
vulnerable code extracted from CVE fix commits. Use `docs/contributing/secure-coding.md`
for the dangerous-vs-safe pattern tables per language.

### Step 3: Write the Rule

Start simple and iterate. For taint mode:

```yaml
rules:
  - id: sql-injection
    languages: [python]
    severity: ERROR
    message: >-
      User input reaches SQL query without parameterization.
      Use parameterized queries instead.
    metadata:
      cwe: CWE-89
      owasp: A03:2021
      confidence: HIGH
    mode: taint
    pattern-sources:
      - pattern: user_input
    pattern-sinks:
      - pattern: $CONN.execute($QUERY, ...)
        focus-metavariable: $QUERY
```

For pattern matching:

```yaml
rules:
  - id: hardcoded-password
    languages: [python]
    severity: WARNING
    message: Hardcoded password in source code
    patterns:
      - pattern: $VAR = "..."
      - metavariable-regex:
          metavariable: $VAR
          regex: "(?i)(password|passwd|secret|token)"
      - metavariable-analysis:
          analyzer: entropy
          metavariable: $VAR
```

### Step 4: Iterate Until All Tests Pass

Run the Go test for your rule:

```bash
# Run a specific test
go test ./test/rules/<lang>/ -run TestMyRule -count=1 -v

# Run all tests for a language
go test ./test/rules/<lang>/ -count=1 -v
```

You can also use `xgrep test` for quick iteration during development, then
write the Go test once the rule is stable:

```bash
xgrep test rules/<lang>/lang/security/<category>/<rule-id>/
```

**Common issues and fixes:**

| Problem | Likely Cause | Fix |
|---------|-------------|-----|
| Expected line not matched | Pattern too specific | Broaden with `...` or `$VAR`, use `pattern-either` |
| Unexpected line matched | Pattern too broad | Add `pattern-not`, `pattern-not-inside`, or metavariable filter |
| Taint not propagating | Missing propagator | Add `pattern-propagators` for assignments/transformations |
| Wrong lines matched | Ellipsis too greedy | Use `pattern-inside` to scope, or set `generic_ellipsis_max` |
| YAML parse error with `:` | Unquoted colon in pattern | Use `pattern: \|` block scalar for patterns with colons |

**Iterate**: Change one thing at a time. Run the test after each change.

### Step 5: Optimize the Rule

Only after all tests pass:

1. **Remove redundant patterns**: If a `pattern-not` never fires, remove it
2. **Simplify combinators**: If all branches of `pattern-either` share structure, factor it out
3. **Re-test after every change**: Optimization can introduce regressions

#### Check what the rule COSTS, not just what it finds

A rule can pass every test and still be a defect. Correctness and cost are
separate properties, and the tests only measure the first.

```bash
# --time reports per-rule evaluation time and findings
xgrep scan --json --time -o /tmp/report.json <a large real codebase>

python3 -c "
import json
rt = json.load(open('/tmp/report.json'))['time']['rule_times']
for r in sorted(rt, key=lambda r: -r['total_seconds'])[:10]:
    n = r.get('findings')
    # absent and zero are different answers: 'the binary did not report it'
    # versus 'the rule ran and found nothing'. Keep them apart explicitly --
    # relying on truthiness gets the right output here only by accident of
    # ordering, which is the kind of thing that breaks when someone reorders it.
    if n is None:
        per = '-  (no findings data)'
    elif n == 0:
        per = 'INF  (ran, found nothing)'
    else:
        per = '%.2fs' % (r['total_seconds'] / n)
    print('%8.1fs  %5s findings  %-24s %s' % (r['total_seconds'], n, per, r['id']))
"
```

**Seconds per finding is the number that matters**, not total time. Two rules
with the same total cost are not comparable: one returning thousands of findings
is doing real work, one returning zero is not. Sorted by total time alone they
sit next to each other, which is why the ratio is the useful key.

**A rule that finds nothing may still be correct.** The flaw may genuinely be
absent from that codebase. What is wrong is the cost of *reaching* that answer --
so never "fix" it by deleting or weakening the rule. Make the negative answer
cheap instead.

#### The cost model for taint rules

Engines pre-filter candidate files using the literal tokens in your **sink**
pattern: if none appears in a file, the whole rule can be skipped before any
taint is seeded. That gate is the difference between a rule costing milliseconds
and one costing minutes.

It fails silently when the sink has no usable literal:

- very short tokens are usually discarded -- too common to filter on
- punctuation and type keywords (`int`, `char`, `*`, `(`) are not distinctive
- a sink of pure syntax -- a cast, an index, a bare dereference -- offers nothing
  to gate on

When the gate cannot engage, cost is driven entirely by how often the **source**
matches. So the pathological shape is:

> **a source that matches everywhere + a sink with no distinctive literal**

Both halves are required. A broad source is fine when the sink gates; a
syntax-only sink is fine when the source is rare.

Before shipping a taint rule, ask:

1. **What literal token would an engine pre-filter my sink on?** If the honest
   answer is "none", expect the rule to visit every file in the codebase.
2. **How often does my source match?** `grep -c` its shape on a real codebase.
   An address-of, a bare assignment or a string literal can appear hundreds of
   thousands of times.
3. If both answers are bad, **anchor one of them** -- name a specific function in
   the sink, or constrain the source to the declaration shape you actually mean.

### Step 6: Final Validation

```bash
# Validate rule syntax
xgrep validate rules/<lang>/lang/security/<category>/<rule-id>/<rule-id>.xgrep.yaml

# Run against CVE sample code to verify detection
xgrep -f <rule>.xgrep.yaml cve/<lang>/lang/security/<category>/ --json

# Run against real code to check for unexpected false positives
xgrep -f <rule>.xgrep.yaml <real-codebase> --json

# Run the Go test suite
go test ./test/rules/<lang>/ -run TestMyRule -count=1 -v
```

Review any matches on real code. If there are false positives, add safe
examples to the source file and update ExpectMatch in the Go test.

---

## Porting an Existing Rule

When given an existing rule and target language(s):

### Step 1: Analyze the Source Rule

Read the existing rule YAML carefully:

1. What vulnerability does it detect?
2. What patterns/sources/sinks does it use?
3. Are there language-specific idioms (decorators, error returns, annotations)?
4. What metavariable filters are applied?

### Step 2: Assess Applicability

For each target language, determine:

- **Directly applicable**: The vulnerability and API pattern exist in the target language (e.g., SQL injection exists in every language with DB access)
- **Applicable with adaptation**: The vulnerability exists but the API surface is different (e.g., Python `subprocess.run` vs Go `exec.Command`)
- **Not applicable**: The pattern doesn't apply (e.g., Python decorator rules don't apply to C)

Check [language-guide.md]({baseDir}/references/language-guide.md) for capabilities and idiom mappings.

### Step 3: Create Target Language Tests

For each applicable target language:

1. Create a new directory: `<rule-id>-<language>/`
2. Write idiomatic test code in the target language
3. Map each test case from the source rule to the target language equivalent
4. Add language-specific edge cases

**Example**: Porting Python SQL injection to Go:

```go
package main

import "database/sql"

func vulnerable(db *sql.DB, userInput string) {
    db.Query("SELECT * FROM users WHERE id = " + userInput)

    query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userInput)
    db.Query(query)
}

func safe(db *sql.DB, userInput string) {
    db.Query("SELECT * FROM users WHERE id = ?", userInput)

    db.Query("SELECT COUNT(*) FROM users")
}
```

Keep the source file annotation-free (as in Step 2): group the vulnerable calls
first, then the safe ones, and record which lines must match in the Go test's
`ExpectMatch` — not with inline `// ruleid:` / `// ok:` comments.

### Step 4: Write the Variant Rule

Create a new rule file adapting patterns for the target language:

- Adjust API calls to target language equivalents
- Adjust string formatting patterns
- Keep the same metadata (CWE, OWASP, severity)
- Use language-appropriate metavariable patterns

### Step 5: Validate

```bash
# Test the new variant
xgrep test <rule-id>-<language>/

# Ensure original rule still passes
xgrep test <original-rule-id>/
```

---

## Common Anti-Patterns

### 1. Missing ellipsis in call arguments

```yaml
# BAD: Only matches single-argument calls
pattern: foo($X)

# GOOD: Matches any number of arguments
pattern: foo($X, ...)
# or
pattern: foo(...)
```

### 2. Forgetting pattern-not for safe wrappers

If `db.query(user_input)` should match but `db.query(sanitize(user_input))` should not:

```yaml
patterns:
  - pattern: $DB.query($INPUT)
  - pattern-not: $DB.query(sanitize(...))
```

### 3. Taint without sanitizer testing

Always write test cases that verify sanitizers actually block findings:

```python
# safe: sanitized before the sink, so the rule must NOT fire here
sanitized = sanitize(user_input)
dangerous(sanitized)
```

### 4. Wrong language identifier

| File Type | Correct `languages` value |
|-----------|--------------------------|
| `.ts` | `typescript` |
| `.tsx` | `tsx` (NOT `typescript`) |
| `.jsx` | `javascript` |
| `.mjs` | `javascript` |
| `.kt` | `kotlin` |
| `.sc` | `scala` |

### 5. Regex when AST patterns would work

`pattern-regex` matches inside strings and comments. Use AST `pattern` when possible. Reserve `pattern-regex` for patterns that can't be expressed as AST patterns (e.g., matching inside string literals, matching whitespace patterns).

### 6. Metavariable comparison without capture

```yaml
# BAD: $SIZE is never captured
patterns:
  - metavariable-comparison:
      metavariable: $SIZE
      comparison: $SIZE > 1024

# GOOD: Pattern captures $SIZE first
patterns:
  - pattern: allocate($SIZE)
  - metavariable-comparison:
      metavariable: $SIZE
      comparison: $SIZE > 1024
```

---

## Silent-Failure Anti-Patterns

The anti-patterns above mostly produce a *wrong* result you can see. These
produce **no result** — the rule validates, runs, and reports nothing (or
quietly reports less than you think). `xgrep validate` says
"1 rules validated successfully" for every one of them.

**Because they are invisible, a passing fixture does not clear them.** When a
new rule finds nothing, work down this list before concluding the target is
clean.

### 7. Trailing ellipsis binds only the LAST argument

`...` is greedy, so a metavariable after it captures only the final argument.
A metavariable *between* two ellipses still never binds a middle argument.

Measured on `log.Print(a, b, secret)` / `(a, secret, b)` / `(secret, a, b)`:

| pattern | last | middle | first |
|---|:--:|:--:|:--:|
| `f(..., $V)` | yes | no | no |
| `f(..., $V, ...)` | yes | **no** | yes |
| `f($V, ...)` | no | no | yes |

```yaml
# BAD: only fires when the secret is the final argument
- pattern: log.Printf(..., $VAR)

# BETTER: also covers the first position
- pattern: log.Printf(..., $VAR, ...)

# For a specific known position, pin it explicitly:
- pattern: scanf($FMT, $BUF, ...)     # first variadic
- pattern: scanf($FMT, ..., $BUF)     # last variadic
```

This bites hardest on variadic sinks, where the interesting value genuinely can
be anywhere: a secret-logging rule written `log.Printf(..., $VAR)` only fires
when the secret happens to be the final argument, and `scanf("%s %d", buf, &n)`
taints `&n` rather than `buf`. Middle-position matching is an engine limitation,
so enumerate the positions explicitly when the value can be anywhere.

### 8. Out-parameter sources need `focus-metavariable`

Functions that write **through** an argument (rather than returning the value)
taint the *buffer*, not the call expression. Without `focus-metavariable` the
taint lands on an expression that reaches no sink and the rule finds nothing.

```yaml
# BAD: taints the call expression (which is a byte COUNT, not the data)
pattern-sources:
  - pattern: read($FD, $BUF, ...)

# GOOD: taint follows the buffer
pattern-sources:
  - patterns:
    - pattern: read($FD, $BUF, ...)
    - focus-metavariable: $BUF
```

Applies to `read`/`recv`/`recvfrom`/`fread`/`fgets`/`gets`/`scanf`/`fscanf`,
`std::getline`, and similar. **Decide from the SINK**: a sink consuming a
*length* (`alloca($N)`, `malloc($N)`) genuinely wants the return value and must
NOT focus the buffer; a sink consuming *content* (a format string, path,
command, query) wants the buffer.

### 9. A shape rule must not carry `subcategory: vuln`

If a rule matches code *shape* without proving untrusted input reaches the sink,
it is a hardening finding — `subcategory: audit`. Reserve `vuln` for
taint-proven detection. Tagging a shape rule `vuln` inflates the exploitable
false-positive rate and buries real findings.

The house pattern is a **pair**: a taint rule (`vuln`, high confidence) plus a
shape rule (`audit`) sharing the sink family.

```yaml
# <rule>-taint : mode: taint, subcategory: vuln  — proven reachable
# <rule>       : shape only,  subcategory: audit — e.g. non-constant format string
```

This one is worth taking seriously: on a large labeled benchmark a single
mis-tagged shape rule can account for the overwhelming majority of a scanner's
apparent false positives, because it fires on every "fixed" variant that still
contains the dangerous construct. Splitting it moves those findings to the audit
tier — where they are still reported — and leaves the vuln tier meaning what it
claims.

### 10. A bare call pattern also matches the DECLARATION

`foo(...)` matches `func foo(a, b string)` — the declaration's parameter list —
not just calls. Used as a presence check ("does this function call `foo`?") it
silently also matches "this file *declares* `foo`", which inverts a gate.

```yaml
# BAD: matches the declaration too
- pattern-inside: |
    func $H(...) { ... getSession(...) ... }

# GOOD: anchor on the call in value position
- pattern-inside: |
    func $H(...) { ... $SID := getSession(...) ... }
```

### 11. Folding `pattern-inside` alternatives collapses source seeding

Several `pattern-inside` variants inside one `pattern-either` seed the source
only **once per file**: a file with three otherwise-identical handlers reports
one finding instead of three. Give each variant its own source block (YAML
anchors keep it readable).

```yaml
# BAD: one alternation -> one finding per file
pattern-sources:
  - patterns:
    - pattern-either: [ ... ]
    - pattern-either:
      - pattern-inside: |
          func $H(...) { ... $S.GetSession(...) ... }
      - pattern-inside: |
          func $H(...) { ... getSession(...) ... }

# GOOD: separate blocks, one per gate variant
pattern-sources:
  - patterns:
    - pattern-either: &req-id [ ... ]
    - pattern-inside: |
        func $H(...) { ... $S.GetSession(...) ... }
  - patterns:
    - pattern-either: *req-id
    - pattern-inside: |
        func $H(...) { ... getSession(...) ... }
```

### Diagnosing a rule that finds nothing

1. Drop the rule to its bare positive `pattern` and confirm that matches at all.
2. Re-add clauses one at a time — the one that zeroes the result is the culprit.
3. For taint rules, test the source and sink patterns **separately** as plain
   `pattern` rules before combining them.
4. Check the target is actually being scanned: a scope filter, `.semgrepignore`
   or language filter can drop every file silently. Scanning a fixture that
   lives under `rules/` is filtered by default — use `--include-tests`.
5. Beware fixture size: a rule can behave differently on a small file than a
   large one, so confirm on a realistic target too.
