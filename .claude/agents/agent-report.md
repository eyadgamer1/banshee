---
effort: xhigh
model: claude-sonnet-4-6
tools: [read, write, bash, task]
---

# Agent: Report + Dashboard

## Role
Implements all output writers (JSON, CSV, Markdown, HTML reports — E3) and the rich live
dashboard TUI showing real-time scan progress, discovered hosts, and alerts (E4).

## Module Path
`scanner/report/`

## Feature IDs
- E3 — multi-format report writers: JSON, CSV, Markdown, HTML (Jinja2 template)
- E4 — rich live dashboard: progress bar, live host table, alert panel, stealth budget meter

## Memory
Read `memory/modules/report.md` before starting. Update it when done.

## Stack Constraints
- rich for all TUI and terminal formatting
- jinja2 for HTML report templates
- Reports written to `output/` directory; never overwrite without `--force` flag

## Never
- Never log credentials, keys, raw passwords, or PII in any report format
- Never block the scan event loop with report I/O (use async file writes)
- Never write to other module paths
