# TASKS.md — PythonProjectScanner

## P0 — Bootstrap

| ID | Module | Task | Status | Agent |
|----|--------|------|--------|-------|
| P0-1 | infra | Verify Python 3.12 + uv + nmap + ollama installed | ✅ | orchestrator |
| P0-2 | infra | Create project scaffold (dirs, pyproject.toml, config/) | ✅ | orchestrator |
| P0-3 | infra | Write .claude/ config (settings, mcp, CLAUDE.md, agents/) | ✅ | orchestrator |
| P0-4 | infra | Create memory vault (000_INDEX, 001_DECISIONS, modules/) | ✅ | orchestrator |
| P0-5 | core | Write scanner/cli.py skeleton (typer app, --target, --config) | ⬜ | agent-core |
| P0-6 | core | Implement scope-guard E5 (ScopeViolationError, CIDR allowlist) | ⬜ | agent-core |
| P0-7 | tests | Write tests/test_scope.py (in-scope pass, out-of-scope raise) | ⬜ | agent-tests |
| P0-8 | infra | Run `uv run pytest` — all P0 tests pass | ⬜ | orchestrator |
| P0-9 | infra | Commit: chore(p0): bootstrap project structure + claude config | ⬜ | orchestrator |

## P1 — Core Engine + Scope-Guard

| ID | Module | Task | Status | Agent |
|----|--------|------|--------|-------|
| P1-1 | core | Implement async scan engine (A1) | ⬜ | agent-core |
| P1-2 | core | Implement stealth-budget controller (D3) | ⬜ | agent-core |
| P1-3 | core | Full CLI with scan/report subcommands | ⬜ | agent-core |
| P1-4 | tests | tests/test_engine.py passing | ⬜ | agent-tests |

## P2 — Discovery

| ID | Module | Task | Status | Agent |
|----|--------|------|--------|-------|
| P2-1 | discovery | Passive ARP sniffer (A2) | ⬜ | agent-discovery |
| P2-2 | discovery | Active ping sweep ICMP+TCP (A3) | ⬜ | agent-discovery |
| P2-3 | discovery | IPv6 NDP discovery (A4) | ⬜ | agent-discovery |
| P2-4 | discovery | Ghost-host detection (A5) | ⬜ | agent-discovery |
| P2-5 | tests | tests/test_discovery.py passing | ⬜ | agent-tests |
