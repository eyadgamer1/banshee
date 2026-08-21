"""E1 — YAML plugin engine.

Loads custom detection rules from YAML files in a directory (default:
config/plugins/) and evaluates them against a ScanResult to produce Findings.

Rule schema (YAML):
  id: PLUG-001
  title: "Open Telnet detected"
  severity: high          # critical | high | medium | low | info
  confidence: confirmed   # confirmed | probable | potential
  description: "Telnet is a clear-text protocol and should be disabled."
  match:
    open_ports:           # list of ints — any match triggers
      - 23
    device_type:          # optional regex against host.device_type
    hostname_regex:       # optional regex against host.hostname
    os_regex:             # optional regex against host.os_guess

Rules are evaluated per-host; a matching rule produces one Finding on that host.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scanner.core.models import Host, ScanResult

log = logging.getLogger(__name__)


def _load_yaml(path: Path) -> Any:
    try:
        import yaml
        with path.open(encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except ImportError:
        log.warning("PyYAML not installed — plugin rules unavailable")
        return None
    except Exception as exc:
        log.warning("Failed to load plugin rule %s: %s", path, exc)
        return None


def _rules_in(doc: Any) -> list[dict[str, Any]]:
    """Extract rule dicts from one loaded YAML document.

    Two file shapes are accepted: a single flat rule (top-level `id`), or a
    `rules:` list holding many. The list form is the natural way to author a
    themed rule pack, so it is the shape the shipped examples use.
    """
    if not isinstance(doc, dict):
        return []
    if "id" in doc:
        return [doc]
    listed = doc.get("rules")
    if isinstance(listed, list):
        return [r for r in listed if isinstance(r, dict) and "id" in r]
    return []


def load_rules(plugin_dir: Path) -> list[dict[str, Any]]:
    """Load all *.yaml / *.yml rule files from plugin_dir."""
    if not plugin_dir.exists():
        return []
    rules = []
    for path in sorted(plugin_dir.glob("*.y*ml")):
        found = _rules_in(_load_yaml(path))
        rules.extend(found)
        for rule in found:
            log.debug("Loaded plugin rule %s from %s", rule["id"], path.name)
    return rules


def _matches(host: Host, match: dict[str, Any]) -> bool:
    """Return True if host satisfies all conditions in the match block."""
    # Port match (ANY)
    required_ports: list[int] = match.get("open_ports") or []
    if required_ports and not any(p in host.open_ports for p in required_ports):
        return False

    # Device type regex
    dt_pattern = match.get("device_type")
    if dt_pattern:
        if not host.device_type or not re.search(dt_pattern, host.device_type, re.I):
            return False

    # Hostname regex
    hn_pattern = match.get("hostname_regex")
    if hn_pattern:
        if not host.hostname or not re.search(hn_pattern, host.hostname, re.I):
            return False

    # OS regex
    os_pattern = match.get("os_regex")
    if os_pattern:
        if not host.os_guess or not re.search(os_pattern, host.os_guess, re.I):
            return False

    return True


def apply_rules(result: ScanResult, rules: list[dict[str, Any]]) -> int:
    """Apply plugin rules to all hosts. Returns count of findings added."""
    from scanner.core.models import ConfidenceTier, Finding, Severity

    _sev_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    _conf_map = {
        "confirmed": ConfidenceTier.CONFIRMED,
        "probable": ConfidenceTier.PROBABLE,
        "potential": ConfidenceTier.POTENTIAL,
    }

    added = 0
    for host in result.hosts:
        for rule in rules:
            match_block = rule.get("match", {})
            if not _matches(host, match_block):
                continue
            finding_id = f"PLUG-{rule['id']}-{host.ip.replace('.', '_')}"
            if any(f.id == finding_id for f in host.findings):
                continue
            sev = _sev_map.get(str(rule.get("severity", "info")).lower(), Severity.INFO)
            conf_key = str(rule.get("confidence", "potential")).lower()
            conf = _conf_map.get(conf_key, ConfidenceTier.POTENTIAL)
            host.findings.append(Finding(
                id=finding_id,
                title=str(rule.get("title", rule["id"])),
                severity=sev,
                confidence=conf,
                description=str(rule.get("description", "")),
                source=f"plugin:{rule['id']}",
            ))
            added += 1
    return added


def run_plugins(result: ScanResult, plugin_dir: Path | None = None) -> int:
    """Load rules from plugin_dir and apply to result. Returns findings added."""
    if plugin_dir is None:
        plugin_dir = Path("config/plugins")
    rules = load_rules(plugin_dir)
    if not rules:
        return 0
    count = apply_rules(result, rules)
    log.info("E1 plugins: %d rules applied, %d findings added", len(rules), count)
    return count
