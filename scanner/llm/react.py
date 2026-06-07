"""D1 — ReAct agentic loop backed by local Ollama.

Implements a minimal Thought → Action → Observation loop that reasons over
a ScanResult and emits structured analysis. Requires Ollama running locally
with a chat-capable model (default: llama3).

Design decisions:
  - Strictly read-only: the agent can only call predefined "tools" that read
    from the ScanResult in memory — it cannot run OS commands or make network calls.
  - Max 10 iterations to prevent runaway loops.
  - Graceful degradation: if Ollama is unreachable, returns a static summary.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scanner.core.models import ScanResult

log = logging.getLogger(__name__)

_DEFAULT_MODEL = "llama3"
_MAX_ITER = 10
_OLLAMA_URL = "http://localhost:11434/api/chat"

# ── Read-only tool definitions exposed to the LLM ────────────────────────────

def _tool_list_hosts(result: ScanResult, **_: Any) -> str:
    rows = []
    for h in result.hosts:
        ports = ",".join(str(p) for p in sorted(h.open_ports)[:10])
        rows.append(
            f"{h.ip}  hostname={h.hostname or '?'}  ports=[{ports}]  "
            f"device={h.device_type or '?'}"
        )
    return "\n".join(rows) if rows else "No hosts discovered."


def _tool_list_findings(result: ScanResult, **_: Any) -> str:
    rows = []
    for h in result.hosts:
        for f in h.findings:
            rows.append(f"[{f.severity.value.upper()}] {h.ip} — {f.title} (id={f.id})")
    return "\n".join(rows) if rows else "No findings."


def _tool_host_detail(result: ScanResult, ip: str = "", **_: Any) -> str:
    for h in result.hosts:
        if h.ip == ip:
            findings = "\n  ".join(f"{f.severity.value}: {f.title}" for f in h.findings)
            return (
                f"IP: {h.ip}\n"
                f"Hostname: {h.hostname}\n"
                f"MAC: {h.mac}\n"
                f"Vendor: {h.vendor}\n"
                f"OS: {h.os_guess}\n"
                f"Device: {h.device_type}\n"
                f"Open ports: {sorted(h.open_ports)}\n"
                f"Findings:\n  {findings or 'none'}"
            )
    return f"Host {ip} not found."


def _tool_pivot_paths(result: ScanResult, **_: Any) -> str:
    try:
        from scanner.correlate import build_attack_graph
        graph = build_attack_graph(result)
        if not graph.edges:
            return "No pivot paths identified."
        lines = [
            f"{e.src} -> {e.dst} via {e.service}:{e.port} [{e.severity.value}]"
            for e in graph.edges[:30]
        ]
        if len(graph.edges) > 30:
            lines.append(f"... and {len(graph.edges) - 30} more edges")
        return "\n".join(lines)
    except Exception as exc:
        return f"Error building attack graph: {exc}"


_TOOLS: dict[str, Any] = {
    "list_hosts": _tool_list_hosts,
    "list_findings": _tool_list_findings,
    "host_detail": _tool_host_detail,
    "pivot_paths": _tool_pivot_paths,
}

_SYSTEM_PROMPT = """\
You are a network security analyst reviewing a passive network scan result.
You have access to the following read-only tools:
  list_hosts()          — list all discovered hosts with ports
  list_findings()       — list all findings with severity
  host_detail(ip=<IP>)  — detailed view of a single host
  pivot_paths()         — lateral movement paths between hosts

Use the ReAct pattern:
  Thought: <your reasoning>
  Action: <tool_name>(<args>)
  Observation: <tool result>
  ... repeat ...
  Final Answer: <your structured analysis>

Rules:
- Only call tools listed above — no OS commands, no network requests.
- Stop when you reach a Final Answer or after 10 iterations.
- Final Answer must include: risk summary, top 3 findings, recommended actions.
"""


async def run_react_loop(result: ScanResult, model: str = _DEFAULT_MODEL) -> str:
    """Run the ReAct loop against `result`. Returns final analysis text."""
    try:
        import aiohttp
    except ImportError:
        log.warning("aiohttp not installed — D1 ReAct loop unavailable")
        return _static_summary(result)

    messages: list[dict[str, str]] = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": "Analyse this scan result and provide a risk assessment."},
    ]

    for iteration in range(_MAX_ITER):
        try:
            async with aiohttp.ClientSession() as session:
                payload = {"model": model, "messages": messages, "stream": False}
                timeout = aiohttp.ClientTimeout(total=60)
                async with session.post(_OLLAMA_URL, json=payload, timeout=timeout) as resp:
                    if resp.status != 200:
                        log.warning("Ollama returned %d", resp.status)
                        break
                    data = await resp.json()
                    assistant_text: str = data["message"]["content"]
        except Exception as exc:
            log.warning("Ollama unreachable: %s", exc)
            return _static_summary(result)

        messages.append({"role": "assistant", "content": assistant_text})

        # Check for Final Answer
        if "Final Answer:" in assistant_text:
            idx = assistant_text.index("Final Answer:")
            return assistant_text[idx + len("Final Answer:"):].strip()

        # Parse Action line
        action_match = re.search(r"Action:\s*(\w+)\(([^)]*)\)", assistant_text)
        if not action_match:
            # No action — treat as done
            return assistant_text.strip()

        tool_name = action_match.group(1)
        args_str = action_match.group(2).strip()
        kwargs: dict[str, str] = {}
        for part in args_str.split(","):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                kwargs[k.strip()] = v.strip().strip("\"'")

        if tool_name not in _TOOLS:
            observation = f"Unknown tool: {tool_name}. Available: {list(_TOOLS)}"
        else:
            try:
                observation = _TOOLS[tool_name](result, **kwargs)
            except Exception as exc:
                observation = f"Tool error: {exc}"

        messages.append({"role": "user", "content": f"Observation: {observation}"})
        log.debug("D1 iter %d: %s → %d chars", iteration + 1, tool_name, len(observation))

    return _static_summary(result)


def _static_summary(result: ScanResult) -> str:
    """Fallback when Ollama is unavailable."""
    n_hosts = len(result.hosts)
    all_findings = [f for h in result.hosts for f in h.findings]
    high_plus = [f for f in all_findings if f.severity.value in ("critical", "high")]
    return (
        f"[Offline summary — Ollama unavailable]\n"
        f"Hosts: {n_hosts} | Findings: {len(all_findings)} | High+: {len(high_plus)}\n"
        f"Run with Ollama running locally (ollama serve) for AI analysis."
    )
