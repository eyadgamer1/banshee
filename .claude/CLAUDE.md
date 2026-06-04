# PythonProjectScanner — Claude Code Instructions

## Project
Passive-first network asset scanner. Discovers, fingerprints, and correlates network
assets. Provides local LLM-assisted risk analysis via Ollama.
**NO exploitation. NO scanning outside config/scope.yaml allowlist.**

## Memory Protocol
1. Read `memory/000_INDEX.md` FIRST every session — phase + module status lives there
2. Subagents: read **and** write ONLY their own `memory/modules/<name>.md`
3. Update module notes LAST, after all changes are committed and tests pass

## Stack
- Python 3.12, asyncio (no threads), uv
- typer + rich (CLI + live dashboard)
- scapy (passive sniff, raw packet fingerprinting)
- aiohttp / httpx (async HTTP probes)
- aiosqlite (persistence layer)
- mypy strict, ruff, pytest + pytest-asyncio

## Hard Rules
- NEVER scan outside `config/scope.yaml` allowlist — ScopeViolationError must raise
- NEVER skip tests before merge — `uv run pytest` must pass green
- NEVER guess library APIs — use Context7 first
- NEVER spawn >10 subagents concurrently
- NEVER delete files without reading them first
- NEVER log credentials, keys, or PII anywhere
- All planning turns: ultrathink effort

## Model Routing
- **Orchestrator**: `claude-opus-4-8` — architecture, planning, cross-module decisions
- **Workers**: `claude-sonnet-4-6` — implementation, each reads its module note first

## Subagent Rule
Each subagent MUST:
1. Read `memory/modules/<own-module>.md` at session start
2. Only modify files in its assigned module path
3. Update `memory/modules/<own-module>.md` before ending session

## Entry Point
```
uv run pps --help
```
