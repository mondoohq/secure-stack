---
name: secure-saas
description: Audit a SaaS tenant or identity provider (GitHub/Okta/Workspace/M365/Slack/…) with cnspec
argument-hint: "<github | gitlab | okta | ms365 | google-workspace | slack | …>"
allowed-tools: Bash Read
---

# Secure a SaaS tenant

**Target:** $ARGUMENTS

Run cnspec against the SaaS API and report its posture.

1. Confirm API credentials for the target (GitHub token + org, Okta org + token, Entra app
   registration, Google service account, Slack token — see cnspec provider docs).
2. Scan with SARIF output (cnspec exits non-zero on failures):
   ```bash
   cnspec scan <provider> [connection flags] -o sarif
   # not logged in to Mondoo Platform? add: --incognito -f <bundle>.mql.yaml
   ```
3. Summarize failures by severity (branch protection, MFA, admin roles, sharing), name the
   control each maps to, and give the remediation. Invoke the `secure-saas` skill for the full
   workflow and bundle list.
