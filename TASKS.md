# TASKS.md — PythonProjectScanner

Coordination: claim → build → tests green → mark ✅ → orchestrator merges.
Workers touch ONLY their module path + their test file + their `memory/modules/<name>.md`.
Workers do NOT run git / uv sync / uv add, and do NOT edit TASKS.md or 000_INDEX.md.

## P0 — Bootstrap ✅

| ID | Module | Task | Status | Agent |
|----|--------|------|--------|-------|
| P0-1..9 | infra | scaffold, .claude/, memory, deps, commit | ✅ | orchestrator |

## P1 — MVP working `pps`  (A1 A3 B1 B2 B6 + C7-lite + dials + E3 + E4-lite + E5)

### Wave 0 — core foundation (orchestrator, blocking)

| ID | Module | Task | Status | Agent |
|----|--------|------|--------|-------|
| P1-0a | core | models.py — Host/Service/Finding/ConfidenceTier/ScanConfig/ScanResult (pydantic) | ✅ | orchestrator |
| P1-0b | core | interfaces.py — Discoverer/Fingerprinter/ReportWriter Protocols + ScanContext | ✅ | orchestrator |
| P1-0c | core | scope.py — E5 ScopeGuard, ScopeViolationError, banner, dry-run, audit-log | ✅ | orchestrator |
| P1-0d | core | budget.py — D3 StealthBudget, --mode + -T0..T5 → concurrency/delay/probe-policy | ✅ | orchestrator |
| P1-0e | core | engine.py — A1 async ScanEngine, target expansion, DI pipeline | ✅ | orchestrator |
| P1-0f | core | cli.py — typer two-dial flags, grouped help, banner, wiring | ✅ | orchestrator |
| P1-0g | tests | test_scope / test_budget / test_engine (core, with fakes) | ✅ | orchestrator |

### Wave 1 — parallel module workers (Sonnet, against frozen core contract)

| ID | Module | Task | Status | Agent |
|----|--------|------|--------|-------|
| P1-1 | discovery | A3 — TCP-connect ping sweep (+ICMP if priv), graceful no-admin | ⬜ | agent-discovery |
| P1-2 | fingerprint | B1 oui (ARP-cache+OUI db) · B2 dhcp (passive, graceful) · B6 name-resolve (rDNS/mDNS/NetBIOS) | ⬜ | agent-fingerprint |
| P1-3 | report | E3 writers txt/json/xml/html/csv · E4-lite rich live progress+table | ⬜ | agent-report |
| P1-4 | risk | C7-lite — ConfidenceTier policy (Confirmed/Probable/Potential tagging) | ⬜ | agent-risk |
| P1-5 | tests | per-module pytest (discovery/fingerprint/report/risk) green | ⬜ | agent-tests |

### Wave 1.5 — integration (orchestrator)

| ID | Module | Task | Status | Agent |
|----|--------|------|--------|-------|
| P1-6 | infra | wire concrete impls → cli/engine; full pytest+ruff+mypy; commit | ⬜ | orchestrator |

## P2 — fingerprint+store (A2 B3 B4 B5 C7 A6 E2 + sarif)  — queued
## P3 — risk+intel+llm (C4 C5 C6 C1 D1 D4 E1 + docx/pdf + LLM)  — queued
## P4 — flagship/EDGE (B7 B8 C2 D3+ B12 D5 D6 A5 A4 B13 + dashboard E4)  — queued
## P5 — moonshots (B9 B10 B11 D2 D7)  — research/optional
