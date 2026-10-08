---
name: triage-findings
description: Scan a codebase with xgrep and classify every finding as true or false positive, with evidence from the code graph
argument-hint: "<target-path>"
allowed-tools: Bash Read Glob Grep
---

# Triage findings

**Target:** $ARGUMENTS (default: current directory)

Execute the full triage workflow automatically:

1. **Scan** the target with xgrep (built-in rules, code graph built automatically):
   ```bash
   xgrep scan --json <target> > /tmp/xgrep-findings.json 2>/dev/null
   ```
   Then read `/tmp/xgrep-findings.json` with the Read tool to parse the JSON.

2. **Summarize**: Count findings by severity and rule ID. Present a table.

3. **Triage** each finding starting with highest severity:
   - Read the finding's `extra.message`, `extra.lines`, and `extra.metadata`
   - Use `context.before`/`context.after` for surrounding code
   - Use `context.function`, `context.callers`, `context.callees` for call graph
   - Check `remediation.description` for fix guidance
   - If more context needed, read the source file directly at the finding's line
   - Classify as: **true positive**, **false positive**, or **needs review**

4. **Report** with a summary table and per-finding details including evidence and remediation.

Notes:
- The code graph is built automatically during scan — no separate `xgrep graph build` needed
- If `remediation.has_autofix` is true, apply the fix with the `xgrep fix` command (`xgrep scan --json … | xgrep fix apply`), or hand it to the `fix-findings` skill
- Use the `triage-findings` skill for detailed investigation methodology by vulnerability type

Invoke the `triage-findings` skill for the full investigation patterns.
