# author-detections

A skill for authoring custom, tested xgrep detection rules to catch a pattern nothing else catches — test-first.

## What it does

- Creates xgrep/Semgrep YAML rules for detecting security vulnerabilities, bug patterns, and code anti-patterns
- Ports existing rules to new target languages with applicability analysis
- Uses test-first methodology: writes test cases before writing the rule
- Iterates until all tests pass with `xgrep test`

## Usage

### Create a new rule

```
/author-detections detect SQL injection via string concatenation in Python
```

### Port an existing rule

```
/author-detections port rules/sql-injection.yaml to Go and Java
```

## Installation

```bash
claude skill install ./skills/author-detections
```

## Prerequisites

- `xgrep` CLI must be installed and available in PATH
- Target codebase should be accessible for real-world validation

## Output

Each rule produces a directory with:
```
<rule-id>/
+-- <rule-id>.yaml     # The xgrep rule
+-- <rule-id>.<ext>    # Test file with ruleid/ok annotations
```
