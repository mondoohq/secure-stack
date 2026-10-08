---
name: author-detections
description: Author a custom, tested xgrep detection rule with a test-first methodology, or port an existing rule to new languages
argument-hint: "(describe what to detect, or provide a rule path + target language)"
allowed-tools: Bash Read Write Edit Glob Grep WebFetch
---

# Author a detection rule

**Arguments:** $ARGUMENTS

This command is context-driven:

- **New rule**: Describe the vulnerability or pattern to detect and the target language
- **Port rule**: Provide an existing rule file path and the target language(s)

If context is unclear, ask for:
1. The vulnerability or code pattern to detect
2. The target language(s)

Invoke the `author-detections` skill for the full workflow.
