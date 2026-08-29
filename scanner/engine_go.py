"""Go active-scan bridge — run the fast, low-memory `banshee-engine` binary and
adopt its result into the Python pipeline.

This is the seam that makes BANSHEE one organism: Go is the hands (parallel TCP
probing, banner grabbing, the adaptive information-gain planner), Python is the
mind (this bridge hands the Go result straight to correlate → plugins → intel →
risk → the report writers, unchanged).

The transport is a subprocess pipe: the Go engine writes a `ScanResult`-shaped
JSON document to stdout, and pydantic rebuilds real typed objects from it — no
bespoke deserializer, because the Go schema mirrors `scanner.core.models`
field-for-field. Python keeps its own `ScanConfig`; only the discovered
hosts/stats come from Go.

Safety is unchanged: the Go binary loads the *same* scope file and enforces it
itself (there is no override flag), and a passive budget puts zero packets on the
wire. This bridge additionally mirrors the Python scope contract — if every
requested target is out of scope, it raises `ScopeViolationError` rather than
returning a silent empty result.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import shutil
import socket
from pathlib import Path
from typing import Any

from scanner.core.models import ScanConfig, ScanResult
from scanner.core.scope import ScopeGuard, ScopeViolationError

log = logging.getLogger(__name__)

# Go exit codes (mirrored from engine/cmd/banshee-engine/main.go). 0 and 3 both
# emit a full JSON document; 3 only signals "nothing was in scope". 1 and 2 are
# hard failures with no JSON on stdout.
_EXIT_OK = 0
_EXIT_NO_TARGETS = 3

_BINARY_NAME = "banshee-engine.exe" if os.name == "nt" else "banshee-engine"


def _build_hint() -> str:
    exe = "banshee-engine.exe" if os.name == "nt" else "banshee-engine"
    return (
        "banshee-engine binary not found. Easiest fix — download the prebuilt engine:\n"
        "  banshee install-engine\n"
        "Or build it from source:\n"
        f"  cd engine && go build -o {exe} ./cmd/banshee-engine\n"
        "then re-run, or set BANSHEE_ENGINE=/path/to/banshee-engine, "
        "or put the binary on your PATH."
    )


def find_engine() -> str:
    """Locate the Go engine binary: $BANSHEE_ENGINE → PATH → repo engine/ dir.

    Raises RuntimeError with a build hint if none is found, so `--engine go`
    fails with actionable guidance rather than an opaque FileNotFoundError.
    """
    env = os.environ.get("BANSHEE_ENGINE")
    if env:
        if Path(env).is_file():
            return env
        raise RuntimeError(f"BANSHEE_ENGINE={env!r} does not point to a file")

    on_path = shutil.which("banshee-engine")
    if on_path:
        return on_path

    # scanner/engine_go.py → repo root → engine/<binary>
    candidate = Path(__file__).resolve().parent.parent / "engine" / _BINARY_NAME
    if candidate.is_file():
        return str(candidate)

    raise RuntimeError(_build_hint())


def resolve_engine(engine: str) -> str:
    """Resolve the ``auto`` engine choice to a concrete one.

    ``auto`` picks the Go engine when its binary is available, else falls back to
    the in-process Python engine. ``python``/``go`` pass through unchanged.
    """
    if engine != "auto":
        return engine
    try:
        find_engine()
        return "go"
    except RuntimeError:
        return "python"


def _needs_dns(token: str) -> bool:
    """True only for a plain hostname — not an IP, CIDR, or IP range.

    IP/CIDR/range tokens are handed to the Go engine untouched (it expands and
    scope-checks them itself); only bare hostnames need Python-side resolution,
    because the Go engine does no DNS.
    """
    token = token.strip()
    try:
        ipaddress.ip_address(token)
        return False
    except ValueError:
        pass
    if "/" in token:
        try:
            ipaddress.ip_network(token, strict=False)
            return False
        except ValueError:
            pass
    if "-" in token:  # an IP range like 10.0.0.1-20 has an IP on the left
        left = token.rsplit("-", 1)[0]
        try:
            ipaddress.ip_address(left)
            return False
        except ValueError:
            pass
    return True


def _lookup_host(name: str) -> list[str]:
    """Resolve a hostname to its IP strings. Blocking — call via an executor.

    Isolated as a module function so it runs off the event loop and so tests can
    substitute it without depending on the platform resolver.
    """
    infos = socket.getaddrinfo(name, None)
    return sorted({str(info[4][0]) for info in infos})


async def resolve_targets(targets: list[str]) -> list[str]:
    """Resolve hostname targets to IPs so the Go engine gets concrete addresses.

    Mirrors the Python engine's behavior (`ScanEngine._resolve`): IP/CIDR/range
    tokens pass through unchanged, hostnames become their resolved IPs, and a name
    that fails to resolve is dropped — exactly as the Python path drops it — so the
    scope contract sees the same target set on either engine.
    """
    loop = asyncio.get_running_loop()
    out: list[str] = []
    for token in targets:
        token = token.strip()
        if not token:
            continue
        if not _needs_dns(token):
            out.append(token)
            continue
        try:
            out.extend(await loop.run_in_executor(None, _lookup_host, token))
        except (socket.gaierror, OSError):
            log.debug("go engine: could not resolve %r; dropping", token)
    return out


def build_args(cfg: ScanConfig, scope_path: str, targets: list[str]) -> list[str]:
    """Translate a ScanConfig into banshee-engine CLI arguments.

    Only flags the operator actually set are passed: the Go engine inherits its
    budget template for any flag left unvisited, so we must not hand it a zero the
    user never typed (that is what its own `optInt` guards against on its side).
    `targets` is the already-resolved address set, not the raw cfg.targets.
    """
    args: list[str] = ["-scope", scope_path, "-mode", cfg.mode.value, "-T", str(cfg.timing)]

    if cfg.ports:
        args += ["-ports", ",".join(str(p) for p in cfg.ports)]
    if cfg.rate is not None:
        args += ["-rate", str(cfg.rate)]
    if cfg.threads is not None:
        args += ["-threads", str(cfg.threads)]
    if cfg.timeout_ms is not None:
        args += ["-timeout", str(cfg.timeout_ms)]
    if cfg.adaptive:
        args.append("-adaptive")
    if cfg.udp:
        args.append("-udp")
    if cfg.service_scan:
        args.append("-sV")
    if not cfg.fingerprint:
        args.append("-banners=false")

    # dry-run is a hard promise of zero packets; force the passive budget rather
    # than trusting mode alone. (The Go engine treats max-detect-risk 0 as passive.)
    if cfg.dry_run:
        args += ["-max-detect-risk", "0"]
    elif cfg.max_detect_risk is not None:
        args += ["-max-detect-risk", str(cfg.max_detect_risk)]

    # Targets are positional and must come after the flags.
    args += list(targets)
    return args


async def run_go_engine(cfg: ScanConfig, guard: ScopeGuard, scope_path: str) -> ScanResult:
    """Run the Go active-scan core and return a `ScanResult` for the Python pipeline.

    `scope_path` is the resolved scope file the Python guard was built from; the Go
    engine loads and enforces it independently. `guard` supplies the authorized-use
    banner so the Go and Python paths produce identical report headers.
    """
    binary = find_engine()

    # Python is the mind: resolve hostnames here so the Go engine (which does no
    # DNS) receives concrete IPs and can scope-check them. If nothing resolves,
    # return an empty result rather than invoking Go with zero targets — the same
    # outcome the Python engine produces when every name fails to resolve.
    resolved = await resolve_targets(cfg.targets)
    if not resolved:
        return ScanResult(config=cfg, banner=guard.banner)

    args = build_args(cfg, scope_path, resolved)
    log.debug("go engine: %s %s", binary, " ".join(args))

    try:
        proc = await asyncio.create_subprocess_exec(
            binary,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        # binary exists but is not runnable: wrong platform, not executable, or a
        # non-binary file pointed at by $BANSHEE_ENGINE.
        raise RuntimeError(
            f"could not run banshee-engine at {binary!r} ({exc}); check it is the right "
            "platform build and is executable"
        ) from exc
    stdout, stderr = await proc.communicate()
    err_text = stderr.decode("utf-8", "replace").strip()

    if proc.returncode not in (_EXIT_OK, _EXIT_NO_TARGETS):
        raise RuntimeError(
            f"banshee-engine failed (exit {proc.returncode}): {err_text or 'no error output'}"
        )
    if err_text:
        # Go prints scope/target warnings to stderr even on success; surface at debug.
        log.debug("go engine stderr: %s", err_text)

    try:
        data: dict[str, Any] = json.loads(stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"banshee-engine produced no valid JSON: {exc}") from exc

    stats = data.get("stats") or {}
    # Mirror the Python engine's scope contract: every requested target out of
    # scope is an attempt to scan unauthorized hosts — refuse loudly, don't return
    # a silent empty result. The CLI maps this to exit code 3, same as the Python path.
    if cfg.targets and int(stats.get("targets_in_scope", 0)) == 0:
        raise ScopeViolationError(
            ", ".join(cfg.targets[:3]) + ("..." if len(cfg.targets) > 3 else ""),
            "no requested target is inside the scope allowlist",
        )

    kwargs: dict[str, Any] = {
        "config": cfg,  # Python keeps its own resolved config, not Go's slice
        "banner": str(data.get("banner") or guard.banner),
        "hosts": data.get("hosts") or [],
        "stats": stats,
    }
    if data.get("started_at"):
        kwargs["started_at"] = data["started_at"]
    if data.get("finished_at"):
        kwargs["finished_at"] = data["finished_at"]
    if data.get("plan"):  # adaptive audit trail — present only with -adaptive
        kwargs["plan"] = data["plan"]

    return ScanResult(**kwargs)
