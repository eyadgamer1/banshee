"""Engine parity — the Go active-scan core and the Python engine must report the
same reality.

Both engines are driven through the *real* CLI against *real* loopback listeners,
and their open-port sets must equal the sockets actually bound — and each other.
This is the cross-engine half of the ground-truth guarantee (see
test_ground_truth.py): a bridge that silently dropped or fabricated a service
would pass a mocked test and fail here.

Skips cleanly when the Go binary is not built, so the suite stays green without
Go toolchain but proves parity wherever `banshee-engine` is present.
"""

from __future__ import annotations

import contextlib
import json
import socket
import threading

import pytest
from typer.testing import CliRunner

from scanner.cli import app
from scanner.engine_go import find_engine

runner = CliRunner()


@pytest.fixture
def go_binary():
    try:
        return find_engine()
    except RuntimeError as exc:  # not built / not on PATH
        pytest.skip(str(exc))


@pytest.fixture
def loopback_scope(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(
        "banner: TEST AUTHORIZED LOOPBACK ONLY\n"
        "allowlist:\n  - 127.0.0.0/8\n"
        "denylist: []\nmax_hosts_per_scan: 16\nmax_ports_per_host: 1000\n",
        encoding="utf-8",
    )
    return str(p)


@contextlib.contextmanager
def listeners(count):
    """Bind `count` TCP listeners on ephemeral loopback ports; yield their ports."""
    socks = []
    try:
        for _ in range(count):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", 0))
            s.listen(8)
            socks.append(s)
        yield [s.getsockname()[1] for s in socks]
    finally:
        for s in socks:
            with contextlib.suppress(OSError):
                s.close()


def closed_port():
    """Reserve then release an ephemeral port, so nothing is listening on it."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextlib.contextmanager
def banner_socket(greeting: bytes):
    """Bind a loopback TCP socket that speaks `greeting` first on accept — a
    server-first service, so -sV can identify it with no active probe."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    s.settimeout(0.3)
    port = s.getsockname()[1]
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = s.accept()
            except (TimeoutError, OSError):
                continue
            with contextlib.suppress(OSError):
                conn.sendall(greeting)
            conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        yield port
    finally:
        stop.set()
        t.join(timeout=1)
        s.close()


@contextlib.contextmanager
def udp_socket(*, reply: bool):
    """Bind a loopback UDP socket. reply=True echoes (provably open); reply=False
    drains but never answers (open|filtered — open yet indistinguishable from filtered).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(0.3)
    port = s.getsockname()[1]
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                data, addr = s.recvfrom(2048)
            except (TimeoutError, OSError):
                continue
            if reply:
                with contextlib.suppress(OSError):
                    s.sendto(b"PONG", addr)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        yield port
    finally:
        stop.set()
        t.join(timeout=1)
        s.close()


def scan(engine, scope_file, tmp_path, ports, binary):
    out = tmp_path / f"{engine}.json"
    result = runner.invoke(
        app,
        [
            "127.0.0.1",
            "--mode", "normal",
            "-T", "4",
            "--sniff-timeout", "0.5",
            "--no-fingerprint",
            "--engine", engine,
            "--ports", ",".join(str(p) for p in ports),
            "--scope", scope_file,
            "--silent",
            "--json", str(out),
        ],
        env={"BANSHEE_ENGINE": binary},
    )
    assert result.exit_code == 0, result.output
    return json.loads(out.read_text(encoding="utf-8"))


def open_ports_of(data, ip="127.0.0.1"):
    for host in data["hosts"]:
        if host["ip"] == ip:
            return {s["port"] for s in host["services"] if s["state"] == "open"}
    return set()


def test_go_engine_matches_ground_truth(go_binary, loopback_scope, tmp_path):
    """The Go engine must report exactly the bound ports, and never a closed one."""
    with listeners(3) as bound:
        shut = closed_port()
        assert shut not in bound
        data = scan("go", loopback_scope, tmp_path, [*bound, shut], go_binary)

    found = open_ports_of(data)
    assert found == set(bound), f"go bound={sorted(bound)} closed={shut} reported={sorted(found)}"
    assert shut not in found, f"go fabricated an open port: {shut} was never bound"


def test_go_and_python_agree(go_binary, loopback_scope, tmp_path):
    """Both engines, same targets, same truth — port-for-port."""
    with listeners(2) as bound:
        shut = closed_port()
        ports = [*bound, shut]
        py = scan("python", loopback_scope, tmp_path, ports, go_binary)
        go = scan("go", loopback_scope, tmp_path, ports, go_binary)

    assert open_ports_of(go) == open_ports_of(py) == set(bound)


def test_go_reports_confirmed_and_sends_packets(go_binary, loopback_scope, tmp_path):
    """A Go-reported port must carry CONFIRMED evidence and a real packet count.

    Proves the confidence tier and source survive the JSON round-trip into pydantic,
    and that packets_sent > 0 separates a real probe from an invented result.
    """
    with listeners(1) as bound:
        data = scan("go", loopback_scope, tmp_path, bound, go_binary)

    host = next(h for h in data["hosts"] if h["ip"] == "127.0.0.1")
    assert host["state"] == "up"
    svc = next(s for s in host["services"] if s["port"] == bound[0])
    assert svc["confidence"] == "confirmed"
    assert svc["source"] == "A3"
    assert data["stats"]["packets_sent"] > 0


def test_go_adaptive_surfaces_plan(go_binary, loopback_scope, tmp_path):
    """--engine go --adaptive must carry the planner's audit trail into the report."""
    with listeners(1) as bound:
        # Well-known ports carry non-baseline device likelihoods, so the planner
        # probes at least one (unlike ephemeral ports); the bound one is truly open.
        ports = [135, 139, 445, *bound]
        out = tmp_path / "adaptive.json"
        result = runner.invoke(
            app,
            [
                "127.0.0.1",
                "--mode", "normal",
                "-T", "4",
                "--sniff-timeout", "0.5",
                "--no-fingerprint",
                "--engine", "go",
                "--adaptive",
                "--ports", ",".join(str(p) for p in ports),
                "--scope", loopback_scope,
                "--silent",
                "--json", str(out),
            ],
            env={"BANSHEE_ENGINE": go_binary},
        )
        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text(encoding="utf-8"))

    plan = data["plan"]
    assert plan is not None, "adaptive scan produced no plan block"
    assert plan["probes_sent"] >= 1
    assert plan["probes_planned"] >= plan["probes_sent"]
    assert plan["probes_saved"] == plan["probes_planned"] - plan["probes_sent"]
    assert plan["verdicts"] and plan["verdicts"][0]["class"], "no device classification"


def test_go_udp_ground_truth(go_binary, loopback_scope, tmp_path):
    """Real UDP through the CLI: a replying port is CONFIRMED open; a silent port is
    open|filtered — the anti-fabrication invariant, end to end."""
    with udp_socket(reply=True) as up_open, udp_socket(reply=False) as up_silent:
        out = tmp_path / "udp.json"
        result = runner.invoke(
            app,
            [
                "127.0.0.1",
                "--mode", "normal",
                "-T", "4",
                "--sniff-timeout", "0.5",
                "--no-fingerprint",
                "--engine", "go",
                "--udp",
                "--ports", f"{up_open},{up_silent}",
                "--scope", loopback_scope,
                "--silent",
                "--json", str(out),
            ],
            env={"BANSHEE_ENGINE": go_binary},
        )
        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text(encoding="utf-8"))

    host = next(h for h in data["hosts"] if h["ip"] == "127.0.0.1")
    svc = {s["port"]: s for s in host["services"]}
    assert svc[up_open]["proto"] == "udp"
    assert svc[up_open]["state"] == "open"
    assert svc[up_open]["confidence"] == "confirmed"
    assert svc[up_silent]["state"] == "open|filtered"
    assert svc[up_silent]["confidence"] == "potential"


def test_go_service_scan_identifies_version(go_binary, loopback_scope, tmp_path):
    """-sV through the real CLI: a server-first banner is parsed to product+version,
    and a silent open port gets no fabricated identity — match-only, end to end."""
    with banner_socket(b"SSH-2.0-OpenSSH_9.9p1 Test\r\n") as speaks, listeners(1) as silent:
        out = tmp_path / "sv.json"
        result = runner.invoke(
            app,
            [
                "127.0.0.1",
                "--mode", "normal",
                "-T", "4",
                "--sniff-timeout", "0.5",
                "--no-fingerprint",
                "--engine", "go",
                "-sV",
                "--ports", f"{speaks},{silent[0]}",
                "--scope", loopback_scope,
                "--silent",
                "--json", str(out),
            ],
            env={"BANSHEE_ENGINE": go_binary},
        )
        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text(encoding="utf-8"))

    host = next(h for h in data["hosts"] if h["ip"] == "127.0.0.1")
    svc = {s["port"]: s for s in host["services"]}
    # Server-first banner -> identified even though --no-fingerprint tried to
    # disable banners (-sV forces them on).
    assert svc[speaks]["product"] == "OpenSSH"
    assert svc[speaks]["version"] == "9.9p1"
    assert svc[speaks]["confidence"] == "confirmed"
    # Silent open port -> open and confirmed, but no invented product/version.
    assert svc[silent[0]]["state"] == "open"
    assert svc[silent[0]]["product"] is None
    assert svc[silent[0]]["version"] is None


def test_out_of_scope_target_is_refused(go_binary, loopback_scope, tmp_path):
    """The Go path must honor the same scope contract: all-out-of-scope → exit 3."""
    out = tmp_path / "oos.json"
    result = runner.invoke(
        app,
        [
            "8.8.8.8",
            "--mode", "normal",
            "--engine", "go",
            "--scope", loopback_scope,
            "--silent",
            "--json", str(out),
        ],
        env={"BANSHEE_ENGINE": go_binary},
    )
    assert result.exit_code == 3, result.output
