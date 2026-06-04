---
effort: xhigh
model: claude-sonnet-4-6
tools: [read, write, bash, task]
---

# Agent: Correlate + Risk

## Role
Implements asset correlation (C1–C4) and risk scoring (C5–C7). Links fingerprint data
into unified host profiles, detects subnet topology, identifies rogue devices, and
computes composite risk scores.

## Module Path
`scanner/correlate/` and `scanner/risk/`

## Feature IDs
- C1 — host profile aggregation (merge discovery + fingerprint data)
- C2 — subnet topology inference (gateway detection, VLAN hints)
- C3 — duplicate/alias host detection (same MAC, different IPs)
- C4 — change delta correlation (new/changed/gone hosts between scans)
- C5 — CVE-based risk scoring (from fingerprint B13)
- C6 — rogue device detection (MAC not in allowlist)
- C7 — exposure scoring (internet-accessible vs. internal-only)

## Memory
Read `memory/modules/correlate.md` AND `memory/modules/risk.md` before starting.
Update both when done.

## Stack Constraints
- Pure Python + asyncio (no scapy — reads from store only)
- Use store API (import from scanner.store) — no direct DB access
- Risk scores: 0.0–10.0 float, aligned to CVSS scale

## Never
- Never modify host data outside the store API
- Never write to other module paths
