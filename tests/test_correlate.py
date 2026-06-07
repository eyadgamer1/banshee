"""C1 attack graph + C2 segment map — pivot/bridge correlation."""

from __future__ import annotations

from scanner.core.models import (
    Host,
    HostState,
    PortState,
    Proto,
    ScanConfig,
    ScanResult,
    Service,
)
from scanner.correlate import build_attack_graph, build_segment_map


def host(ip: str, ports: list[int], device_type: str | None = None) -> Host:
    return Host(
        ip=ip,
        state=HostState.UP,
        device_type=device_type,
        services=[Service(port=p, proto=Proto.TCP, state=PortState.OPEN) for p in ports],
    )


def result(hosts: list[Host]) -> ScanResult:
    return ScanResult(config=ScanConfig(), hosts=hosts)


def test_no_pivot_edges_for_single_host():
    r = result([host("10.0.0.1", [445])])
    g = build_attack_graph(r)
    assert g.edges == []
    assert g.pivot_targets() == []


def test_pivot_edges_between_two_smb_hosts():
    r = result([host("10.0.0.1", [445]), host("10.0.0.2", [445])])
    g = build_attack_graph(r)
    assert len(g.edges) == 2  # each reachable from the other
    assert g.pivot_targets() == ["10.0.0.1", "10.0.0.2"]


def test_pivot_finding_attached():
    r = result([host("10.0.0.1", [3389]), host("10.0.0.2", [3389])])
    build_attack_graph(r)
    assert any(f.id.startswith("C1-pivot-") for f in r.hosts[0].findings)


def test_pivot_severity_uses_highest_service():
    r = result([host("10.0.0.1", [80, 445]), host("10.0.0.2", [80, 445])])
    build_attack_graph(r)
    f = next(f for f in r.hosts[0].findings if f.id.startswith("C1-pivot"))
    assert f.severity.value == "high"  # SMB beats HTTP


def test_build_attack_graph_idempotent():
    # Regression: calling twice (CLI + agentic tool) must not duplicate findings.
    r = result([host("10.0.0.1", [445]), host("10.0.0.2", [445])])
    build_attack_graph(r)
    build_attack_graph(r)
    pivot_findings = [f for f in r.hosts[0].findings if f.id.startswith("C1-pivot")]
    assert len(pivot_findings) == 1


def test_non_pivot_ports_ignored():
    # port 12345 is not a known pivot service
    r = result([host("10.0.0.1", [12345]), host("10.0.0.2", [12345])])
    g = build_attack_graph(r)
    assert g.edges == []


def test_segment_map_single_subnet():
    r = result([host("192.168.1.1", [80]), host("192.168.1.2", [80])])
    smap = build_segment_map(r)
    assert len(smap.segments) == 1
    assert smap.segments[0].network.startswith("192.168.1.0")


def test_segment_map_multiple_subnets():
    r = result([host("192.168.1.1", [80]), host("192.168.2.1", [80])])
    smap = build_segment_map(r)
    assert len(smap.segments) == 2


def test_segment_bridge_finding_for_router():
    r = result([
        host("192.168.1.1", [80], device_type="router"),
        host("192.168.2.1", [80]),
    ])
    smap = build_segment_map(r)
    assert "192.168.1.1" in smap.bridges
    assert any(f.id.startswith("C2-bridge-") for f in r.hosts[0].findings)


def test_segment_map_empty_result():
    smap = build_segment_map(result([]))
    assert smap.segments == []
    assert smap.bridges == []


def test_attack_graph_to_dict():
    r = result([host("10.0.0.1", [22]), host("10.0.0.2", [22])])
    g = build_attack_graph(r)
    d = g.to_dict()
    assert d and set(d[0]) == {"src", "dst", "service", "port", "severity"}
