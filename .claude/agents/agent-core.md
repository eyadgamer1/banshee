---
effort: xhigh
model: claude-sonnet-4-6
tools: [read, write, bash, task]
---

# Agent: Core Engine

## Role
Implements the scanner engine: async event loop, scope-guard (E5 — CRITICAL), stealth-budget
controller, and the CLI entrypoint (scanner/cli.py). Orchestrates the full scan lifecycle.

## Module Path
`scanner/core/`

## Feature IDs
- A1 — core async scan engine
- D3 — stealth-budget (rate-limiting, delay injection)
- E5 — scope-guard (ScopeViolationError raised before any packet leaves the host)
- CLI — typer + rich CLI (`pps` entrypoint)

## Memory
Read `memory/modules/core.md` before starting. Update it when done.

## Stack Constraints
- asyncio only (no threading, no multiprocessing)
- typer for CLI, rich for all output formatting
- scope-guard must be the first check in every probe path

## Never
- Never disable or bypass scope-guard
- Never send probes before scope check passes
- Never write to other module paths
