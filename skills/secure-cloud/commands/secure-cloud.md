---
name: secure-cloud
description: Audit a cloud account (AWS/Azure/GCP/K8s) against CIS foundations and Mondoo cloud policies with cnspec
argument-hint: "<aws | azure | gcp | k8s>"
allowed-tools: Bash Read
---

# Secure a cloud account

**Target:** $ARGUMENTS

Run cnspec against the cloud account and report its posture.

1. Confirm credentials for the target cloud are available (AWS profile, Azure login, gcloud
   credentials, or kube context).
2. Scan with SARIF output (cnspec exits non-zero on failures):
   ```bash
   cnspec scan <aws|azure|gcp|k8s> -o sarif
   # not logged in to Mondoo Platform? add: --incognito -f <bundle>.mql.yaml
   ```
3. Summarize failures by severity, name the CIS/compliance control each maps to, and give the
   remediation (IAM, network, storage, encryption, logging). Invoke the `secure-cloud` skill for
   the full workflow and bundle list.
