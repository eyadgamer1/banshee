"""Core data-model behaviour: derived properties and confidence defaults."""

from __future__ import annotations

from scanner.core.models import (
    ConfidenceTier,
    Finding,
    Host,
    HostState,
    PortState,
    Proto,
    ScanConfig,
    ScanResult,
    Service,
    Severity,
)


def test_best_name_prefers_hostname_then_mdns_then_rdns_then_ip():
    h = Host(ip="10.0.0.1")
    assert h.best_name == "10.0.0.1"
    h.names["rdns"] = "r.example"
    assert h.best_name == "r.example"
    h.names["mdns"] = "m.local"
    assert h.best_name == "m.local"  # mdns beats rdns
    h.hostname = "host.lan"
    assert h.best_name == "host.lan"  # hostname wins outright


def test_open_ports_sorted_and_open_only():
    h = Host(
        ip="10.0.0.1",
        services=[
            Service(port=443, state=PortState.OPEN),
            Service(port=22, state=PortState.OPEN),
            Service(port=8080, state=PortState.CLOSED),
            Service(port=139, state=PortState.FILTERED),
        ],
    )
    assert h.open_ports == [22, 443]


def test_service_defaults_confirmed_tcp_open():
    s = Service(port=80)
    assert s.proto is Proto.TCP
    assert s.state is PortState.OPEN
    assert s.confidence is ConfidenceTier.CONFIRMED


def test_finding_defaults_potential_info():
    f = Finding(id="X", title="t")
    assert f.severity is Severity.INFO
    assert f.confidence is ConfidenceTier.POTENTIAL
    assert f.is_llm_inferred is False


def test_up_hosts_filters_state():
    r = ScanResult(
        config=ScanConfig(),
        hosts=[
            Host(ip="10.0.0.1", state=HostState.UP),
            Host(ip="10.0.0.2", state=HostState.DOWN),
            Host(ip="10.0.0.3", state=HostState.UNKNOWN),
        ],
    )
    assert [h.ip for h in r.up_hosts] == ["10.0.0.1"]


def test_first_last_seen_populated():
    h = Host(ip="10.0.0.1")
    assert h.first_seen is not None
    assert h.last_seen is not None


def test_null_collections_coerced_to_empty():
    """A JSON producer (e.g. the Go engine) may send null for an empty collection.

    default_factory does not fire when the key is present-but-null, so the
    validators must coerce None -> []/{} or the --engine go bridge would fail with
    a pydantic list_type error on any host that has no open ports.
    """
    h = Host.model_validate({"ip": "10.0.0.1", "services": None, "findings": None, "names": None})
    assert h.services == []
    assert h.findings == []
    assert h.names == {}

    r = ScanResult.model_validate({"config": ScanConfig().model_dump(), "hosts": None})
    assert r.hosts == []


def test_config_engine_defaults_to_python():
    cfg = ScanConfig()
    assert cfg.engine == "python"
    assert cfg.adaptive is False
