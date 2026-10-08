---
name: secure-os
description: Audit and harden an OS or network device with cnspec against CIS/vendor benchmarks, mapped to compliance
argument-hint: "<target: local | ssh user@host | docker image|container | device>"
allowed-tools: Bash Read
---

# Secure an OS / device

**Target:** $ARGUMENTS

Run cnspec against the target and report its hardening + vulnerability posture.

1. Resolve the connection: `local`, `ssh <user>@<host>`, `docker <image|container>`, or a
   network device (see cnspec provider docs for device auth).
2. Scan with SARIF output (cnspec exits non-zero on failures):
   ```bash
   cnspec scan <target> -o sarif
   # not logged in to Mondoo Platform? add: --incognito -f <bundle>.mql.yaml
   ```
   Pick the bundle for the target (`mondoo-linux-security`, `mondoo-macos-security`,
   `mondoo-windows-security`, or the relevant network-device bundle).
3. Summarize failures by severity, name the CIS/vendor control each maps to, and give the
   concrete remediation. Invoke the `secure-os` skill for the full workflow and bundle list.
