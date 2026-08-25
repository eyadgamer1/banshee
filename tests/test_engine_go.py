"""Unit tests for the Go bridge (`scanner.engine_go`) — offline, no binary needed.

These pin the bridge's own logic: hostname resolution (the Go engine does no DNS,
so Python must hand it concrete IPs), argument construction, and binary discovery
with its build hint. The live cross-engine behavior is covered by
test_engine_parity.py, which needs the built binary.
"""

from __future__ import annotations

import socket

import pytest

from scanner.core.models import ScanConfig, ScanMode
from scanner.engine_go import (
    _needs_dns,
    build_args,
    find_engine,
    resolve_engine,
    resolve_targets,
)


def _fake_lookup(table):
    """Return a `_lookup_host` stand-in resolving only names in `table`.

    Keeps these tests offline and fast: real DNS (especially a failing lookup) can
    stall the platform resolver for many seconds, and it must not gate CI.
    """
    def lookup(name):
        if name in table:
            return table[name]
        raise socket.gaierror(f"name or service not known: {name}")

    return lookup


def test_needs_dns_only_for_hostnames():
    assert _needs_dns("scanme.nmap.org") is True
    assert _needs_dns("host-1.lan") is True  # a '-' in a name is not an IP range
    # IPs, CIDRs and IP-ranges are handed to Go untouched.
    assert _needs_dns("127.0.0.1") is False
    assert _needs_dns("10.0.0.0/24") is False
    assert _needs_dns("10.0.0.1-20") is False
    assert _needs_dns("10.0.0.1-10.0.0.20") is False
    assert _needs_dns("::1") is False


async def test_resolve_targets_resolves_names_and_passes_ips_through(monkeypatch):
    fake = _fake_lookup({"myhost.lan": ["10.9.9.9"]})
    monkeypatch.setattr("scanner.engine_go._lookup_host", fake)
    out = await resolve_targets(["myhost.lan", "10.0.0.0/30", "8.8.8.8", "10.0.0.1-5"])
    assert "10.9.9.9" in out  # hostname resolved to its IP
    # IP/CIDR/range tokens survive verbatim for Go to expand + scope-check.
    assert "10.0.0.0/30" in out
    assert "8.8.8.8" in out
    assert "10.0.0.1-5" in out


async def test_resolve_targets_drops_unresolvable(monkeypatch):
    monkeypatch.setattr("scanner.engine_go._lookup_host", _fake_lookup({}))
    out = await resolve_targets(["no-such-host.lan"])
    assert out == []  # dropped, exactly as the Python engine drops a failed name


def test_build_args_maps_flags():
    cfg = ScanConfig(
        targets=["example-name"], mode=ScanMode.NORMAL, timing=4,
        ports=[22, 80], adaptive=True, fingerprint=False,
    )
    args = build_args(cfg, "scope.yaml", ["127.0.0.1"])
    assert args[:2] == ["-scope", "scope.yaml"]
    assert "-mode" in args and "normal" in args
    assert "22,80" in args
    assert "-adaptive" in args
    assert "-banners=false" in args  # --no-fingerprint
    assert args[-1] == "127.0.0.1"  # resolved target is positional, last


def test_build_args_dry_run_forces_zero_risk():
    cfg = ScanConfig(targets=["127.0.0.1"], mode=ScanMode.NORMAL, dry_run=True, max_detect_risk=7)
    args = build_args(cfg, "scope.yaml", ["127.0.0.1"])
    i = args.index("-max-detect-risk")
    assert args[i + 1] == "0"  # dry-run wins over any max-detect-risk value


def test_resolve_engine_auto_picks_go_when_built(monkeypatch):
    monkeypatch.setattr("scanner.engine_go.find_engine", lambda: "/x/banshee-engine")
    assert resolve_engine("auto") == "go"


def test_resolve_engine_auto_falls_back_to_python(monkeypatch):
    def boom():
        raise RuntimeError("not built")

    monkeypatch.setattr("scanner.engine_go.find_engine", boom)
    assert resolve_engine("auto") == "python"
    # explicit choices always pass through unchanged
    assert resolve_engine("python") == "python"
    assert resolve_engine("go") == "go"


def test_find_engine_rejects_bad_env(monkeypatch, tmp_path):
    monkeypatch.setenv("BANSHEE_ENGINE", str(tmp_path / "nonexistent"))
    with pytest.raises(RuntimeError, match="does not point to a file"):
        find_engine()


def test_find_engine_gives_build_hint_when_absent(monkeypatch):
    monkeypatch.delenv("BANSHEE_ENGINE", raising=False)
    monkeypatch.setattr("scanner.engine_go.shutil.which", lambda _: None)
    monkeypatch.setattr("scanner.engine_go._BINARY_NAME", "definitely-not-a-real-binary.xyz")
    with pytest.raises(RuntimeError, match="go build"):
        find_engine()
