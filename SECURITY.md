# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a vulnerability

Don't open a public issue for security bugs.

Email: eyadyasser4002@gmail.com

Include the version (`banshee --version`), what you found, steps to reproduce, and the potential impact. I'll respond within 72 hours and push a fix within 14 days if it's confirmed.

## Hard limits in the codebase

These can't be configured away:

- `ScopeViolationError` is always raised for out-of-scope targets
- No payload generation, no shellcode, no active attack capability
- `--enrich` is the only feature that contacts external servers — it's opt-in and shows a warning
- Credentials, keys, and PII are never written to the audit log
