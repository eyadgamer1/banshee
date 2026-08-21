"""E3 report writers — all six formats serialize correctly and safely."""

from __future__ import annotations

import csv
import json
from xml.etree import ElementTree as ET

import pytest

from scanner.core.models import (
    ConfidenceTier,
    Finding,
    Host,
    HostState,
    PortState,
    Proto,
    ScanConfig,
    ScanResult,
    ScanStats,
    Service,
    Severity,
)
from scanner.report.writers import all_writers


def sample_result() -> ScanResult:
    host = Host(
        ip="10.0.0.5",
        state=HostState.UP,
        hostname="host.lan",
        mac="aa:bb:cc:dd:ee:ff",
        vendor="VMware",
        os_guess="Linux",
        device_type="server",
        confidence=ConfidenceTier.CONFIRMED,
        services=[Service(port=22, proto=Proto.TCP, state=PortState.OPEN, name="ssh")],
        findings=[
            Finding(id="F1", title="Telnet exposed", severity=Severity.HIGH,
                    confidence=ConfidenceTier.PROBABLE, description="bad", source="C1"),
        ],
    )
    return ScanResult(
        config=ScanConfig(targets=["10.0.0.5"]),
        banner="TEST BANNER",
        hosts=[host],
        stats=ScanStats(hosts_up=1, services_found=1, findings=1, targets_in_scope=1),
    )


@pytest.fixture
def writers():
    return all_writers()


def test_all_six_formats_registered(writers):
    assert set(writers) == {"txt", "json", "xml", "html", "csv", "sarif"}


def test_json_roundtrips(writers, tmp_path):
    p = tmp_path / "out.json"
    writers["json"].write(sample_result(), p)
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["hosts"][0]["ip"] == "10.0.0.5"
    assert data["stats"]["hosts_up"] == 1


def test_csv_has_header_and_row(writers, tmp_path):
    p = tmp_path / "out.csv"
    writers["csv"].write(sample_result(), p)
    rows = list(csv.reader(p.read_text(encoding="utf-8").splitlines()))
    assert rows[0][0] == "ip"
    assert rows[1][0] == "10.0.0.5"
    assert "22" in rows[1][-1]  # open_ports column


def test_xml_is_wellformed(writers, tmp_path):
    p = tmp_path / "out.xml"
    writers["xml"].write(sample_result(), p)
    root = ET.parse(p).getroot()
    assert root.tag == "scan"
    host_el = root.find("./hosts/host")
    assert host_el is not None
    assert host_el.get("ip") == "10.0.0.5"


def test_txt_contains_banner_and_finding(writers, tmp_path):
    p = tmp_path / "out.txt"
    writers["txt"].write(sample_result(), p)
    text = p.read_text(encoding="utf-8")
    assert "TEST BANNER" in text
    assert "Telnet exposed" in text
    assert "10.0.0.5" in text


def test_html_renders_and_escapes(writers, tmp_path):
    r = sample_result()
    r.hosts[0].findings.append(
        Finding(id="X", title="<script>alert(1)</script>", severity=Severity.LOW)
    )
    p = tmp_path / "out.html"
    writers["html"].write(r, p)
    html = p.read_text(encoding="utf-8")
    assert "<html" in html.lower()
    # autoescape must neutralise injected markup
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_sarif_schema_basics(writers, tmp_path):
    p = tmp_path / "out.sarif"
    writers["sarif"].write(sample_result(), p)
    doc = json.loads(p.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "pps"
    assert run["results"][0]["ruleId"] == "F1"
    assert run["results"][0]["level"] == "error"  # HIGH -> error


def test_sarif_includes_ssvc_when_present(writers, tmp_path):
    r = sample_result()
    r.hosts[0].findings[0].ssvc_priority = "IMMEDIATE"
    p = tmp_path / "out.sarif"
    writers["sarif"].write(r, p)
    doc = json.loads(p.read_text(encoding="utf-8"))
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["ssvc_priority"] == "IMMEDIATE"


def test_writers_create_parent_dirs(writers, tmp_path):
    p = tmp_path / "nested" / "deep" / "out.json"
    writers["json"].write(sample_result(), p)
    assert p.exists()


def test_empty_result_txt(writers, tmp_path):
    r = ScanResult(config=ScanConfig(), banner="B")
    p = tmp_path / "empty.txt"
    writers["txt"].write(r, p)
    assert "(no live hosts)" in p.read_text(encoding="utf-8")
