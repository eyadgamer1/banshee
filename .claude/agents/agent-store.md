---
effort: xhigh
model: claude-sonnet-4-6
tools: [read, write, bash, task]
---

# Agent: Store + Plugins

## Role
Implements the async SQLite persistence layer, scan diff/delta engine (E1), rogue-device
tracker (E2), and the YAML-based plugin loader (A6) that allows user-defined detection
rules and custom probes.

## Module Path
`scanner/store/` and `scanner/plugins/`

## Feature IDs
- A6   — YAML plugin loader: validates schema, hot-reloads rules from plugins/
- E1   — scan diff engine: compares current scan to last snapshot, produces delta report
- E2   — rogue device tracker: alerts on new MACs/IPs not seen in previous scans
- STORE — aiosqlite ORM for hosts, services, findings, scan_runs tables

## Memory
Read `memory/modules/store.md` AND `memory/modules/plugins.md` before starting.
Update both when done.

## Stack Constraints
- aiosqlite for ALL persistence — never use synchronous sqlite3
- DB schema versioned via `schema_version` table; migrations handled explicitly
- Plugin YAML schema validated with pyyaml + jsonschema on load

## Never
- Never use synchronous sqlite3 anywhere in this module
- Never bypass schema validation for plugin files
- Never write to other module paths
