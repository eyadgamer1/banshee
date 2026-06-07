# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: eyadyasser4002@gmail.com

Include:
- BANSHEE version (`banshee --version`)
- Description of the vulnerability
- Steps to reproduce
- Potential impact

You will receive a response within 72 hours. If confirmed, a patch will be released within 14 days.

## Security Constraints (Hard-Coded)

These are invariants in the codebase, not configuration options. PRs that weaken them will be rejected:

1. **Scope guard** — `ScopeViolationError` is always raised for out-of-scope targets. It cannot be disabled.
2. **No exploitation** — The engine emits findings only. No payload generation, no shellcode, no weaponized output.
3. **External data opt-in** — `--enrich` is the only flag that contacts external APIs. It is off by default and shows a loud warning when enabled.
4. **No credential logging** — The audit trail records IPs and events only. Keys, passwords, and PII are never written to disk.
