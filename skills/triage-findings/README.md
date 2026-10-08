# triage-findings

A skill for deciding whether a security finding is real — classifying xgrep scan findings as true or false positives using code-graph dataflow analysis.

## What it does

- Scans targets with xgrep rules and summarizes findings
- Investigates each finding using the code graph (callers, callees, call paths, function context)
- Classifies findings as true positive, false positive, or needs review
- Provides evidence-based reports with specific function names and line numbers
- Suggests remediation for true positives

## Usage

```
/triage-findings ./src --rules security-rules/
```

## Installation

```bash
claude skill install ./skills/triage-findings
```

## Prerequisites

- `xgrep` CLI must be installed and available in PATH
- Target codebase must be accessible for graph building

## Investigation Capabilities

- **Injection** (SQL, command, XSS): Traces data from sources to sinks, checks for sanitization
- **Auth/access control**: Maps all entry points, verifies middleware coverage
- **Data exposure**: Tracks sensitive data flow to logging, errors, and API responses
- **Insecure configuration**: Checks environment-specific overrides
- **Cryptographic issues**: Evaluates algorithm and key management context
