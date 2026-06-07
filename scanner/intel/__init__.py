"""Intel module — external enrichment and prioritization (C4, C5).

Integration contract:
  - `enrich_result(result)` — C4: attach EPSS scores + KEV flags (needs --enrich, data leaves host)
  - `prioritize_result(result)` — C5: SSVC priority tags on each finding (local, always safe)
"""

from __future__ import annotations

from scanner.intel.epss import enrich_result
from scanner.intel.ssvc import SsvcPriority, prioritize_result

__all__ = ["SsvcPriority", "enrich_result", "prioritize_result"]
