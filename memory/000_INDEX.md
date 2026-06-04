---
type: index
project: PythonProjectScanner
---

# PythonProjectScanner — Memory Index

**Project**: Passive-first network asset scanner. Discovers, fingerprints, and correlates
network assets using local LLM-assisted analysis. No exploitation. Scope-guarded.

---

## Phase Tracker

| Phase | Name | Status |
|-------|------|--------|
| P0 | Bootstrap & Config | 🔄 |
| P1 | Core Engine + Scope-Guard | ⬜ |
| P2 | Discovery Modules | ⬜ |
| P3 | Fingerprint + Correlate + Risk | ⬜ |
| P4 | Intel + LLM + Report | ⬜ |
| P5 | Store + Plugins + Integration | ⬜ |

---

## Module Status

| Module | Path | Status | Feature IDs |
|--------|------|--------|-------------|
| core | scanner/core/ | ⬜ | A1, D3, E5, CLI |
| discovery | scanner/discovery/ | ⬜ | A2, A3, A4, A5 |
| fingerprint | scanner/fingerprint/ | ⬜ | B1–B13 |
| correlate | scanner/correlate/ | ⬜ | C1–C4 |
| risk | scanner/risk/ | ⬜ | C5–C7 |
| intel | scanner/intel/ | ⬜ | D1, D2, D4, D5, D6 |
| llm | scanner/llm/ | ⬜ | LLM-1, LLM-2, LLM-3 |
| report | scanner/report/ | ⬜ | E3, E4 |
| store | scanner/store/ | ⬜ | A6, E1, E2, STORE |
| plugins | scanner/plugins/ | ⬜ | A6 (YAML engine) |

---

## Module Notes
- [[memory/modules/core]]
- [[memory/modules/discovery]]
- [[memory/modules/fingerprint]]
- [[memory/modules/correlate]]
- [[memory/modules/risk]]
- [[memory/modules/intel]]
- [[memory/modules/llm]]
- [[memory/modules/report]]
- [[memory/modules/store]]
- [[memory/modules/plugins]]

---

## Sessions
See `memory/sessions/` for per-session summaries.
