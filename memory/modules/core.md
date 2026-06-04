---
status: 🔄 Wave 0 done
module: core
---

# Module: core

## Feature IDs
- A1 engine · D3 budget · E5 scope · CLI — all Wave-0 complete

## Entry Points
- `core/models.py` — Host/Service/Finding/ScanConfig/ScanResult, ConfidenceTier (StrEnum)
- `core/interfaces.py` — Discoverer/Fingerprinter/ReportWriter Protocols, ScanContext
- `core/scope.py` — ScopeGuard.from_file, ScopeViolationError, AuditLog (JSONL)
- `core/budget.py` — StealthBudget.from_config (mode×timing→limits)
- `core/engine.py` — ScanEngine.run, expand_target, RunContext
- `cli.py` — typer `app` (entry `pps`), two-dial flags, wiring

## Decisions
- DI via Protocols: engine never imports concrete modules; CLI wires them.
- PASSIVE or --max-detect-risk 0 => allow_active_probes False (zero packets).
- Out-of-scope targets filtered+audited (not raised) in engine flow.
- Terminal output ASCII-only (Windows cp1252 console).

## Deps
- pydantic, zeroconf added P1. types-PyYAML (dev).
