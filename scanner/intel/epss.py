"""C4 — EPSS / CISA KEV enrichment.

Fetches EPSS scores (Exploit Prediction Scoring System) from the FIRST.org API
and checks CVE IDs against the CISA Known Exploited Vulnerabilities catalogue.

Both calls are opt-in (require `--enrich` flag in the CLI), async, and guarded
by the scope/budget layer so nothing is sent without explicit user consent.

WARNING: enabling --enrich sends CVE identifiers to external APIs.
The CLI prints a loud "data leaves host" notice before making any requests.

Offline fallback: if requests fail (no network, rate-limit), findings keep
their existing confidence/severity and no exception propagates.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.models import Finding, ScanResult

log = logging.getLogger(__name__)

_EPSS_URL = "https://api.first.org/data/v1/epss"
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

# In-process cache for the session — avoids duplicate network calls
_epss_cache: dict[str, float] = {}
_kev_cache: set[str] | None = None


async def _fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    """Return {cve_id: epss_score} for the given list. Batches up to 100."""
    if not cve_ids:
        return {}
    try:
        import aiohttp
    except ImportError:
        return {}

    results: dict[str, float] = {}
    # Batch into groups of 100 (API limit)
    for i in range(0, len(cve_ids), 100):
        batch = cve_ids[i : i + 100]
        uncached = [c for c in batch if c not in _epss_cache]
        if uncached:
            params = {"cve": ",".join(uncached)}
            try:
                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession() as session:
                    async with session.get(_EPSS_URL, params=params, timeout=timeout) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for item in data.get("data", []):
                                cve = item.get("cve", "")
                                score = float(item.get("epss", 0.0))
                                _epss_cache[cve] = score
            except Exception as exc:
                log.debug("EPSS fetch failed: %s", exc)
        for cve in batch:
            if cve in _epss_cache:
                results[cve] = _epss_cache[cve]
    return results


async def _fetch_kev() -> set[str]:
    """Return set of CVE IDs in CISA KEV catalogue."""
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(_KEV_URL, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    _kev_cache = {v["cveID"] for v in data.get("vulnerabilities", [])}
                    return _kev_cache
    except Exception as exc:
        log.debug("KEV fetch failed: %s", exc)
    _kev_cache = set()
    return _kev_cache


def _cves_in(*texts: str) -> list[str]:
    """All distinct CVE IDs (upper-cased) found across the given text fields."""
    found: list[str] = []
    for text in texts:
        found.extend(m.upper() for m in _CVE_RE.findall(text))
    return list(dict.fromkeys(found))  # de-dup, preserve order


def _extract_cves(findings: list[Finding]) -> list[str]:
    cves: list[str] = []
    for f in findings:
        cves.extend(_cves_in(f.title, f.description, f.evidence or ""))
    return list(dict.fromkeys(cves))


async def enrich_result(result: ScanResult) -> None:
    """Attach EPSS scores and KEV flags to findings that reference CVE IDs.

    Only called when `--enrich` is active. Mutates result in place.
    DATA LEAVES HOST when this runs.
    """
    all_findings: list[Finding] = [f for h in result.hosts for f in h.findings]
    cves = _extract_cves(all_findings)
    if not cves:
        return

    log.info("C4 enriching %d CVEs via EPSS+KEV (data leaves host)", len(cves))
    epss_scores, kev_set = await asyncio.gather(_fetch_epss(cves), _fetch_kev())

    from scanner.core.models import Severity

    for host in result.hosts:
        for finding in host.findings:
            cve_ids = _cves_in(finding.title, finding.description, finding.evidence or "")
            if not cve_ids:
                continue

            # Attach highest EPSS score found in this finding
            scores = [epss_scores[c] for c in cve_ids if c in epss_scores]
            if scores:
                max_score = max(scores)
                finding.evidence = (finding.evidence or "") + f" [EPSS={max_score:.3f}]"
                # Escalate severity if EPSS >= 0.5 (high exploitation probability)
                _escalatable = (Severity.LOW, Severity.MEDIUM, Severity.INFO)
                if max_score >= 0.5 and finding.severity in _escalatable:
                    finding.severity = Severity.HIGH

            # Flag KEV membership
            kev_matches = [c for c in cve_ids if c in kev_set]
            if kev_matches:
                finding.evidence = (finding.evidence or "") + f" [KEV:{','.join(kev_matches)}]"
                finding.severity = Severity.CRITICAL
