"""E3 — multi-format report writers.

One small class per format, each satisfying the ReportWriter protocol
(`format_name` + `write(result, path)`). Writers are pure serializers: they never
touch the network and never emit credentials or PII (the models carry none). XML
is *generated* (not parsed) via the stdlib; HTML is rendered through an
autoescaping Jinja2 template, so host-supplied strings cannot inject markup.
"""

from __future__ import annotations

import csv
import io
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING
from xml.etree import ElementTree as ET

from jinja2 import Environment, FileSystemLoader, select_autoescape

if TYPE_CHECKING:
    from jinja2 import Template

    from scanner.core.interfaces import ReportWriter
    from scanner.core.models import Finding, Host, ScanResult, Service

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_HTML_TEMPLATE = "report.html.j2"
_CSV_COLUMNS = (
    "ip",
    "hostname",
    "state",
    "mac",
    "vendor",
    "os_guess",
    "device_type",
    "confidence",
    "open_ports",
)


def _prepare(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


class JsonWriter:
    """Loss-less JSON — the canonical machine-readable artifact."""

    format_name = "json"

    def write(self, result: ScanResult, path: Path) -> None:
        _prepare(path).write_text(result.model_dump_json(indent=2), encoding="utf-8")


class CsvWriter:
    """One row per host; open ports collapsed into a semicolon list."""

    format_name = "csv"

    def write(self, result: ScanResult, path: Path) -> None:
        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer)
        writer.writerow(_CSV_COLUMNS)
        for host in result.hosts:
            writer.writerow(
                [
                    host.ip,
                    host.hostname or "",
                    host.state.value,
                    host.mac or "",
                    host.vendor or "",
                    host.os_guess or "",
                    host.device_type or "",
                    host.confidence.value,
                    ";".join(str(p) for p in host.open_ports),
                ]
            )
        # newline="" keeps csv's \r\n terminators intact (no Windows \r\r\n doubling).
        _prepare(path).write_text(buffer.getvalue(), encoding="utf-8", newline="")


class TxtWriter:
    """Human-readable plain-text report (no ANSI)."""

    format_name = "txt"

    def write(self, result: ScanResult, path: Path) -> None:
        lines: list[str] = [
            result.banner,
            "pps scan report",
            f"mode: {result.config.mode.value}   started: "
            f"{result.started_at.isoformat(timespec='seconds')}",
            "",
            f"hosts up: {result.stats.hosts_up}   services: {result.stats.services_found}   "
            f"findings: {result.stats.findings}",
            f"in-scope: {result.stats.targets_in_scope}   "
            f"out-of-scope: {result.stats.targets_out_of_scope}   "
            f"packets: {result.stats.packets_sent}",
            "",
        ]
        for host in result.hosts:
            lines.extend(self._host_block(host))
        if not result.hosts:
            lines.append("(no live hosts)")
        _prepare(path).write_text("\n".join(lines) + "\n", encoding="utf-8")

    @staticmethod
    def _host_block(host: Host) -> list[str]:
        block = [f"{host.ip}  ({host.best_name})  [{host.confidence.value}]  {host.state.value}"]
        if host.mac:
            block.append(f"    mac: {host.mac}" + (f"  ({host.vendor})" if host.vendor else ""))
        if host.os_guess:
            block.append(f"    os: {host.os_guess}")
        if host.names:
            block.append("    names: " + ", ".join(f"{k}={v}" for k, v in host.names.items()))
        for svc in host.services:
            block.append(
                f"    {svc.port}/{svc.proto.value} {svc.state.value} "
                f"{svc.name or ''} [{svc.confidence.value}]".rstrip()
            )
        for finding in host.findings:
            block.append(
                f"    [{finding.severity.value.upper()}] {finding.title} "
                f"[{finding.confidence.value}]"
            )
        block.append("")
        return block


class XmlWriter:
    """Nmap-flavoured XML, generated with the stdlib (no external parser)."""

    format_name = "xml"

    def write(self, result: ScanResult, path: Path) -> None:
        root = ET.Element("scan", banner=result.banner, mode=result.config.mode.value)
        stats = ET.SubElement(root, "stats")
        for key, value in result.stats.model_dump().items():
            stats.set(key, str(value))
        hosts_el = ET.SubElement(root, "hosts")
        for host in result.hosts:
            self._host_el(hosts_el, host)
        tree = ET.ElementTree(root)
        ET.indent(tree)
        _prepare(path)
        tree.write(path, encoding="utf-8", xml_declaration=True)

    def _host_el(self, parent: ET.Element, host: Host) -> None:
        host_el = ET.SubElement(
            parent,
            "host",
            ip=host.ip,
            state=host.state.value,
            confidence=host.confidence.value,
        )
        if host.best_name:
            host_el.set("name", host.best_name)
        if host.mac:
            host_el.set("mac", host.mac)
        if host.vendor:
            host_el.set("vendor", host.vendor)
        services_el = ET.SubElement(host_el, "services")
        for svc in host.services:
            self._service_el(services_el, svc)
        findings_el = ET.SubElement(host_el, "findings")
        for finding in host.findings:
            self._finding_el(findings_el, finding)

    @staticmethod
    def _service_el(parent: ET.Element, svc: Service) -> None:
        el = ET.SubElement(
            parent,
            "service",
            port=str(svc.port),
            proto=svc.proto.value,
            state=svc.state.value,
            confidence=svc.confidence.value,
        )
        if svc.name:
            el.set("name", svc.name)

    @staticmethod
    def _finding_el(parent: ET.Element, finding: Finding) -> None:
        el = ET.SubElement(
            parent,
            "finding",
            id=finding.id,
            severity=finding.severity.value,
            confidence=finding.confidence.value,
        )
        el.text = finding.title


@lru_cache(maxsize=1)
def _html_template() -> Template:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(("html", "j2", "html.j2")),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return env.get_template(_HTML_TEMPLATE)


class HtmlWriter:
    """Standalone HTML report rendered from an autoescaping Jinja2 template."""

    format_name = "html"

    def write(self, result: ScanResult, path: Path) -> None:
        rendered = _html_template().render(result=result)
        _prepare(path).write_text(rendered, encoding="utf-8")


class SarifWriter:
    """SARIF 2.1.0 — machine-readable findings for security tooling integration."""

    format_name = "sarif"
    _SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    _VERSION = "2.1.0"

    def write(self, result: ScanResult, path: Path) -> None:
        import json as _json

        rules: list[dict[str, object]] = []
        results: list[dict[str, object]] = []
        seen_rules: set[str] = set()

        for host in result.hosts:
            for finding in host.findings:
                rule_id = finding.id
                if rule_id not in seen_rules:
                    seen_rules.add(rule_id)
                    rules.append(
                        {
                            "id": rule_id,
                            "name": finding.title.replace(" ", ""),
                            "shortDescription": {"text": finding.title},
                            "defaultConfiguration": {
                                "level": self._sarif_level(finding.severity.value)
                            },
                            "properties": {"tags": ["network", "discovery"]},
                        }
                    )
                results.append(
                    {
                        "ruleId": rule_id,
                        "level": self._sarif_level(finding.severity.value),
                        "message": {
                            "text": (
                                finding.description
                                or f"{finding.title} on {host.ip} "
                                f"[confidence={finding.confidence.value}]"
                            )
                        },
                        "locations": [
                            {
                                "logicalLocations": [
                                    {
                                        "name": host.ip,
                                        "kind": "host",
                                        "fullyQualifiedName": host.best_name,
                                    }
                                ]
                            }
                        ],
                        "properties": {
                            "confidence": finding.confidence.value,
                            "source": finding.source,
                            "is_llm_inferred": finding.is_llm_inferred,
                            **(
                                {"ssvc_priority": finding.ssvc_priority}
                                if finding.ssvc_priority
                                else {}
                            ),
                        },
                    }
                )

        sarif: dict[str, object] = {
            "$schema": self._SCHEMA,
            "version": self._VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "pps",
                            "informationUri": "https://github.com/eyadgamer1/pps",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "properties": {
                        "mode": result.config.mode.value,
                        "started_at": result.started_at.isoformat(),
                        "hosts_up": result.stats.hosts_up,
                    },
                }
            ],
        }
        _prepare(path).write_text(_json.dumps(sarif, indent=2), encoding="utf-8")

    @staticmethod
    def _sarif_level(severity: str) -> str:
        return {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }.get(severity, "note")


def all_writers() -> dict[str, ReportWriter]:
    """Format-name -> writer instance for every E3 format."""
    writers: tuple[ReportWriter, ...] = (
        JsonWriter(),
        CsvWriter(),
        TxtWriter(),
        XmlWriter(),
        HtmlWriter(),
        SarifWriter(),
    )
    return {w.format_name: w for w in writers}
