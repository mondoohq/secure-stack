# xgrep Rule Quick Reference

## CLI Commands

```bash
# Test rules against annotated test files
xgrep test <directory>

# Validate rule YAML syntax
xgrep validate <path>

# Scan with rules
xgrep -f <rules.yaml> <target>
xgrep -f <rules.yaml> --json <target>     # JSON output
xgrep -f <rules.yaml> --sarif <target>    # SARIF output

# Filter by severity
xgrep -f <rules.yaml> --severity ERROR <target>

# Filter by rule ID
xgrep -f <rules.yaml> --rule-id my-rule <target>

# Apply fixes (scan is read-only; the separate `fix` command writes)
xgrep scan -f <rules.yaml> --json <target> | xgrep fix verify -f <rules.yaml>  # preview, no write
xgrep scan -f <rules.yaml> --json <target> | xgrep fix apply  -f <rules.yaml>  # apply
```

## Rule Structure

```yaml
rules:
  - id: rule-id                    # Unique identifier
    languages: [python]            # Target language(s)
    severity: ERROR                # ERROR, WARNING, INFO
    message: Description with $VAR # Metavariable interpolation
    metadata:                      # Optional metadata
      cwe: CWE-89
      owasp: A03:2021
      confidence: HIGH
    # ... pattern operators below
```

## Pattern Operators

### Basic Patterns

| Operator | Purpose | Example |
|----------|---------|---------|
| `pattern` | Match AST pattern | `pattern: eval(...)` |
| `pattern-regex` | Match regex | `pattern-regex: "password\\s*="` |
| `pattern-not` | Exclude pattern | `pattern-not: eval("safe")` |
| `pattern-not-regex` | Exclude regex | `pattern-not-regex: "test_"` |

### Containment

| Operator | Purpose | Example |
|----------|---------|---------|
| `pattern-inside` | Match only inside | `pattern-inside: \|`<br>`  def $FUNC(...): ...` |
| `pattern-not-inside` | Exclude if inside | `pattern-not-inside: \|`<br>`  try: ... except: ...` |
| `pattern-anywhere` | Match anywhere in file | `pattern-anywhere: import os` |

### Combinators

```yaml
# AND: all must match
patterns:
  - pattern: $X.execute($QUERY)
  - pattern-not: $X.execute("...")

# OR: any can match
pattern-either:
  - pattern: eval(...)
  - pattern: exec(...)

# Nested: combine freely
patterns:
  - pattern-either:
      - pattern: eval($X)
      - pattern: exec($X)
  - pattern-not-inside: |
      if is_safe($X):
          ...
```

## Metavariables

| Syntax | Matches |
|--------|---------|
| `$VAR` | Any single AST node |
| `$...ARGS` | Zero or more arguments/statements |
| `$_` | Any node (anonymous, no binding) |

**Consistency**: When `$X` appears multiple times in a `patterns` block, it must match the same value.

### Metavariable Filters

```yaml
patterns:
  - pattern: $FUNC($ARG)

  # Regex filter on captured value
  - metavariable-regex:
      metavariable: $FUNC
      regex: "(eval|exec|compile)"

  # Nested pattern filter
  - metavariable-pattern:
      metavariable: $ARG
      pattern: request.$METHOD(...)

  # Numeric comparison
  - metavariable-comparison:
      metavariable: $SIZE
      comparison: $SIZE > 1024

  # Type filter
  - metavariable-type:
      metavariable: $X
      type: string

  # Analysis (entropy, redos)
  - metavariable-analysis:
      analyzer: entropy
      metavariable: $TOKEN
```

### Focus Metavariable

Narrow the reported match to a specific metavariable:

```yaml
patterns:
  - pattern: $FUNC($ARG, ...)
  - metavariable-regex:
      metavariable: $FUNC
      regex: "dangerous_.*"
  - focus-metavariable: $ARG
```

## Taint Mode

```yaml
rules:
  - id: sql-injection
    languages: [python]
    severity: ERROR
    message: SQL injection via $SOURCE
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form[...]
    pattern-sinks:
      - pattern: cursor.execute($QUERY, ...)
        focus-metavariable: $QUERY
    pattern-sanitizers:
      - pattern: sanitize(...)
      - pattern: int(...)
    pattern-propagators:
      - pattern: $TO = $FROM.format(...)
        from: $FROM
        to: $TO
```

### Taint Options

```yaml
options:
  # Unify metavariables across source/sink patterns
  taint_unify_mvs: true
  # Cross-file taint tracking
  interfile: true

pattern-sources:
  - pattern: user_input()
    label: USER           # Label for requires/replace-labels
    by-side-effect: true  # Source taints via mutation, not return

pattern-sinks:
  - pattern: dangerous($X)
    requires: USER        # Only fires if taint has this label
    at-exit: true         # Check taint at function exit

pattern-sanitizers:
  - pattern: validate($X)
    not_conflicting: true # Only sanitize if no other taint paths exist
```

## Autofix

```yaml
# Simple replacement with metavariable interpolation
fix: safe_eval($ARG)

# Regex-based replacement
fix-regex:
  regex: "http://"
  replacement: "https://"
  count: 1    # Replace only first occurrence
```

## Rule Options

```yaml
options:
  constant_propagation: true     # Track constant values (default: true)
  symbolic_propagation: true     # Track symbolic expressions
  ac_matching: true              # Associative-commutative matching
  fq_naming: true                # Fully-qualified name resolution
  generic_ellipsis_max: 10       # Max statements matched by ...
  taint_unify_mvs: true          # Unify metavars in taint mode
  interfile: true                # Cross-file analysis
```

## Path Filtering

```yaml
paths:
  include:
    - "src/**"
  exclude:
    - "test/**"
    - "vendor/**"
```

## Version Constraints

```yaml
min-version: 1.0.0
max-version: 2.0.0
```

## Test Annotations

| Annotation | Meaning |
|------------|---------|
| `# ruleid: my-rule` | Next line MUST match |
| `# ok: my-rule` | Next line must NOT match |
| `# todoruleid: my-rule` | Known limitation (expected to match but doesn't yet) |
| `# todook: my-rule` | Known limitation (matches but shouldn't yet) |

Multiple rules: `# ruleid: rule-a, rule-b`

Comment styles by language:
- `#` — Python, Ruby, Bash, YAML
- `//` — Go, Java, JavaScript, TypeScript, C, C++, Rust, Kotlin, Scala, PHP
- `--` — Lua, OCaml
- `<!-- -->` — HTML, XML

## Special Modes

### Join Mode

Correlate findings across sub-rules:

```yaml
mode: join
rules:
  - id: find-source
    pattern: $SOURCE = user_input()
    languages: [python]
  - id: find-sink
    pattern: dangerous($INPUT)
    languages: [python]
on:
  - find-source.$SOURCE == find-sink.$INPUT
```

### Extract Mode

Extract embedded language from host language:

```yaml
mode: extract
languages: [python]
pattern: query = "$QUERY"
dest-language: sql
dest-rules:
  - sql-injection-rules.yaml
```

## Suppression

Suppress findings inline:

```python
eval(safe_input)  # nosemgrep: my-rule
eval(safe_input)  # nogrep: my-rule
eval(safe_input)  # nosemgrep
```
