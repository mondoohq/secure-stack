---
name: secure-coding
description: Review code for security vulnerabilities and provide secure coding guidance across Go, Python, JavaScript, Java, Ruby, C#, and Swift. Triggers on code review, security questions, and vulnerability prevention.
allowed-tools: Bash Read Edit Glob Grep
---

# Secure Coding

Proactively avoid generating vulnerable code. When writing, reviewing, or
modifying code, check against the pattern tables in this skill to use safe
alternatives instead of dangerous patterns.

## When to Use

- Reviewing code for security issues
- Writing new code that handles user input, secrets, HTTP requests, file I/O, or crypto
- Answering "is this safe?" or "how do I securely..." questions
- Generating code that touches authentication, authorization, or data validation

## When NOT to Use

- Writing xgrep detection rules (use `xgrep-rule-creator` skill)
- Triaging existing SAST scan findings (use `xgrep-triage` skill)
- Non-security code questions (algorithms, performance, etc.)

## Detecting Intent

**Code review**: User shares code or asks to review a file/PR for security issues.
**Secure alternative**: User asks how to do something safely ("how do I compare secrets in Go?").
**Proactive**: User is writing code that touches a security-sensitive area.

## Quick Reference -- Most Critical Patterns

### Never Do This

| Pattern | Why | Safe Alternative |
|---------|-----|-----------------|
| `secret == expected` | Timing attack | Constant-time compare (see patterns.md) |
| `"SELECT * FROM t WHERE id=" + input` | SQL injection | Parameterized queries |
| `eval(user_input)` | Code execution | `json.loads()`, `ast.literal_eval()` |
| `requests.get(user_url)` | SSRF | URL allowlist validation |
| `open(user_filename)` | Path traversal | `os.path.basename()` + join |
| `pickle.load(data)` / `yaml.load(data)` | Deserialization RCE | `json.loads()` / `yaml.safe_load()` |
| `jwt.decode(token, secret)` (no algorithms) | JWT alg confusion | `jwt.decode(token, secret, algorithms=["HS256"])` |
| `InsecureSkipVerify: true` | MitM attack | Remove or set `false` |
| `Math.random()` for tokens | Predictable | `crypto.randomBytes()` |
| `tls.Config{MinVersion: tls.VersionTLS10}` | Deprecated TLS | `MinVersion: tls.VersionTLS12` |

## References

- Full per-language pattern tables: [references/patterns.md]({baseDir}/references/patterns.md)
- Real CVE code examples: [references/cve-examples.md]({baseDir}/references/cve-examples.md)

## If `xgrep guard` Blocks an Action

When the xgrep guard hook blocks a prompt or tool call, it names the rule and where
it matched (never the value). Treat that as a security finding, not an obstacle:

- **Never work around it.** Don't rephrase, split, encode or move the command into a
  script to get past the guard, and don't edit, disable or uninstall the hook.
- **Explain and ask.** Tell the user which rule fired, why it is risky, and offer a
  safe alternative (download, inspect, then run; read a secret from the environment).
- **Treat a flagged secret as exposed.** Recommend rotating it and remove it from the
  content instead of retrying.
- **The allowlist is the user's call.** Only the user adds rule ids to
  `.xgrep/guard-allow.txt`.

## Review Checklist

When reviewing code, check for these in order:

```
Security Review:
- [ ] Secret comparison uses constant-time function
- [ ] SQL queries use parameterized placeholders
- [ ] No eval/exec/compile on untrusted input
- [ ] HTTP requests validate URLs against allowlist
- [ ] File paths validated against base directory
- [ ] Deserialization uses safe loaders with type restrictions
- [ ] JWT decoding specifies allowed algorithms
- [ ] TLS >= 1.2, certificate validation enabled
- [ ] Crypto RNG used for security values (not math/rand)
- [ ] No secrets in log output
- [ ] CORS restricted to specific origins
- [ ] HTTP response headers don't include unsanitized user input
- [ ] File creation uses atomic mode setting (no chmod race)
- [ ] XSS: output encoded for context (HTML, JS, URL)
```
