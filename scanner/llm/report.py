"""D4 — LLM-generated executive report via local Ollama.

Generates a natural-language executive summary of the scan result using a
locally running Ollama model. Requires Ollama running at localhost:11434.

Output: plain-text (Markdown) report suitable for inclusion in HTML/PDF.
Graceful degradation: returns structured template if Ollama is unreachable.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.models import ScanResult

log = logging.getLogger(__name__)


_PROMPT_TEMPLATE = """\
You are a senior network security analyst. Write an executive summary report for the
following network scan results. The audience is a non-technical manager.

Include:
1. **Executive Summary** (2-3 sentences)
2. **Key Findings** (bullet list, severity labels, plain English)
3. **Risk Assessment** (overall risk level: Critical/High/Medium/Low)
4. **Recommended Actions** (numbered, prioritized)

Scan data:
{scan_data}

Keep the report concise (max 600 words). Use Markdown formatting.
"""


def _build_scan_data(result: ScanResult) -> str:
    lines = [
        f"Scan mode: {result.config.mode.value}",
        (f"Duration: {(result.finished_at - result.started_at).total_seconds():.1f}s"
         if result.finished_at else ""),
        f"Hosts discovered: {len(result.hosts)}",
    ]
    total_findings = sum(len(h.findings) for h in result.hosts)
    lines.append(f"Total findings: {total_findings}")

    sev_counts: dict[str, int] = {}
    for h in result.hosts:
        for f in h.findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
    if sev_counts:
        by_sev = ", ".join(f"{k}={v}" for k, v in sev_counts.items())
        lines.append("Findings by severity: " + by_sev)

    lines.append("\nTop findings:")
    count = 0
    for h in result.hosts:
        for f in h.findings:
            if count >= 10:
                break
            lines.append(f"  [{f.severity.value.upper()}] {h.ip}: {f.title}")
            count += 1

    return "\n".join(ln for ln in lines if ln)


async def generate_report(result: ScanResult, model: str | None = None) -> str:
    """Generate executive report. Returns Markdown string."""
    scan_data = _build_scan_data(result)
    prompt = _PROMPT_TEMPLATE.format(scan_data=scan_data)

    try:
        import aiohttp
    except ImportError:
        log.warning("aiohttp not installed — D4 report generation unavailable")
        return _fallback_report(result)

    from scanner.core.settings import load_settings

    settings = load_settings()
    model = model or settings.llm_model

    messages = [
        {"role": "system", "content": "You are a professional network security analyst."},
        {"role": "user", "content": prompt},
    ]

    try:
        # Report generation is one long completion, not a loop — allow more than
        # the per-call chat timeout.
        timeout = aiohttp.ClientTimeout(total=settings.llm_timeout_seconds * 2)
        async with aiohttp.ClientSession() as session:
            payload = {"model": model, "messages": messages, "stream": False}
            async with session.post(
                settings.ollama_chat_url, json=payload, timeout=timeout
            ) as resp:
                if resp.status != 200:
                    log.warning("Ollama returned HTTP %d for report generation", resp.status)
                    return _fallback_report(result)
                data = await resp.json()
                return str(data["message"]["content"])
    except Exception as exc:
        log.warning("Ollama unreachable for report generation: %s", exc)
        return _fallback_report(result)


def _fallback_report(result: ScanResult) -> str:
    """Static Markdown report when Ollama is unavailable."""
    all_findings = [f for h in result.hosts for f in h.findings]
    high_plus = [f for f in all_findings if f.severity.value in ("critical", "high")]

    overall = "High" if high_plus else ("Medium" if all_findings else "Low")

    lines = [
        "## Executive Summary",
        "",
        f"A network scan of {len(result.hosts)} hosts completed in "
        f"{result.config.mode.value} mode. "
        f"{len(all_findings)} finding(s) were identified, "
        f"{len(high_plus)} rated High or Critical.",
        "",
        "## Key Findings",
        "",
    ]
    for h in result.hosts:
        for f in h.findings:
            lines.append(f"- **[{f.severity.value.upper()}]** `{h.ip}` — {f.title}")

    lines += [
        "",
        "## Risk Assessment",
        "",
        f"Overall risk level: **{overall}**",
        "",
        "## Recommended Actions",
        "",
        "1. Review all Critical and High findings immediately.",
        "2. Verify no unauthorized devices are present (check rogue detections).",
        "3. Patch services with known CVEs (see EPSS/KEV flags if --enrich was used).",
        "4. Re-scan after remediation to confirm resolution.",
        "",
        "> *Note: LLM-generated analysis unavailable (Ollama offline). "
        "Run `ollama serve` for AI-assisted reporting.*",
    ]
    return "\n".join(lines)
