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
import json
import logging
import os
import shutil
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
        "banshee-engine binary not found. Build it with:\n"
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


def build_args(cfg: ScanConfig, scope_path: str) -> list[str]:
    """Translate a ScanConfig into banshee-engine CLI arguments.

    Only flags the operator actually set are passed: the Go engine inherits its
    budget template for any flag left unvisited, so we must not hand it a zero the
    user never typed (that is what its own `optInt` guards against on its side).
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
    if not cfg.fingerprint:
        args.append("-banners=false")

    # dry-run is a hard promise of zero packets; force the passive budget rather
    # than trusting mode alone. (The Go engine treats max-detect-risk 0 as passive.)
    if cfg.dry_run:
        args += ["-max-detect-risk", "0"]
    elif cfg.max_detect_risk is not None:
        args += ["-max-detect-risk", str(cfg.max_detect_risk)]

    # Targets are positional and must come after the flags.
    args += list(cfg.targets)
    return args


async def run_go_engine(cfg: ScanConfig, guard: ScopeGuard, scope_path: str) -> ScanResult:
    """Run the Go active-scan core and return a `ScanResult` for the Python pipeline.

    `scope_path` is the resolved scope file the Python guard was built from; the Go
    engine loads and enforces it independently. `guard` supplies the authorized-use
    banner so the Go and Python paths produce identical report headers.
    """
    binary = find_engine()
    args = build_args(cfg, scope_path)
    log.debug("go engine: %s %s", binary, " ".join(args))

    proc = await asyncio.create_subprocess_exec(
        binary,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
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

    return ScanResult(**kwargs)
