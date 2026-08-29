"""Fetch the prebuilt Go engine so `--engine go` works without a Go toolchain.

The Python package cannot bundle a compiled binary (a Linux build won't run on
Windows/macOS), so the engine ships as a per-OS asset on GitHub Releases. This
module downloads the asset matching the current platform and drops it next to the
installed `banshee` executable — which is already on PATH — so
``find_engine()`` (PATH lookup) picks it up with no extra configuration.

Stdlib only: no new dependency is pulled into the wheel for this.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from rich.console import Console

_REPO = "eyadgamer1/banshee"
_USER_AGENT = "banshee-engine-installer"
_BINARY_NAME = "banshee-engine.exe" if os.name == "nt" else "banshee-engine"

# (system, machine) -> release asset name. machine values are normalized first.
_ASSETS: dict[tuple[str, str], str] = {
    ("linux", "amd64"): "banshee-engine-linux-amd64",
    ("linux", "arm64"): "banshee-engine-linux-arm64",
    ("darwin", "amd64"): "banshee-engine-darwin-amd64",
    ("darwin", "arm64"): "banshee-engine-darwin-arm64",
    ("windows", "amd64"): "banshee-engine-windows-amd64.exe",
}

# Normalize the many spellings uname/platform report for the same arch.
_ARCH_ALIASES: dict[str, str] = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "x64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
}


class EngineInstallError(RuntimeError):
    """Raised when the engine cannot be downloaded or won't run once fetched."""


def _asset_name(system: str, machine: str) -> str:
    """Map a platform to its release asset name, or raise a clear error."""
    sys_key = system.lower()
    arch = _ARCH_ALIASES.get(machine.lower())
    asset = _ASSETS.get((sys_key, arch or ""))
    if asset is None:
        supported = ", ".join(sorted(f"{s}/{m}" for s, m in _ASSETS))
        raise EngineInstallError(
            f"no prebuilt engine for {system}/{machine}. "
            f"Supported: {supported}. Build from source instead: "
            "cd engine && go build -o banshee-engine ./cmd/banshee-engine"
        )
    return asset


def _dest_dir() -> Path:
    """Where to place the binary: alongside the installed `banshee` launcher, using
    its on-PATH location and NOT its symlink target.

    `uv tool install` puts a shim in `~/.local/bin` (on PATH) that points into the
    tool's venv bin (NOT on PATH). Resolving the symlink would drop the engine in
    the venv, where neither `shutil.which("banshee-engine")` nor `--engine go` can
    ever find it — the exact failure this avoids. So we keep the launcher's own
    directory (the on-PATH one)."""
    banshee = shutil.which("banshee")
    if banshee:
        return Path(banshee).parent
    subdir = ".local/bin" if os.name != "nt" else "AppData/Local/banshee/bin"
    return Path.home() / subdir


def _latest_tag() -> str:
    """Return the latest release tag from the GitHub API."""
    url = f"https://api.github.com/repos/{_REPO}/releases/latest"
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (trusted host)
            data = json.load(resp)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise EngineInstallError(
            f"could not query the latest release ({exc}). Check your network, or "
            "pass an explicit tag, e.g. `banshee install-engine --tag v1.3.0`."
        ) from exc
    tag = data.get("tag_name")
    if not tag:
        raise EngineInstallError("the latest release has no tag_name")
    return str(tag)


def _download(url: str, dest: Path) -> None:
    """Stream a URL to dest, following redirects (urllib does this by default)."""
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 (trusted host)
            fd, tmp_name = tempfile.mkstemp(dir=str(dest.parent), prefix=".banshee-engine-")
            tmp = Path(tmp_name)
            try:
                with os.fdopen(fd, "wb") as out:
                    shutil.copyfileobj(resp, out)
                tmp.replace(dest)
            except BaseException:
                tmp.unlink(missing_ok=True)
                raise
    except urllib.error.HTTPError as exc:
        raise EngineInstallError(
            f"download failed (HTTP {exc.code}) for {url}. If the tag is wrong, "
            "list releases at https://github.com/eyadgamer1/banshee/releases."
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise EngineInstallError(f"download failed for {url}: {exc}") from exc


def _make_executable(path: Path) -> None:
    if os.name != "nt":  # POSIX: set the execute bits Git-less downloads lack
        mode = path.stat().st_mode
        path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _verify_runs(path: Path) -> None:
    """Run the binary once so an arch mismatch fails here with a clear message,
    not later mid-scan. Any exit code counts as "runs"; only a failure to exec
    (wrong architecture / not a binary) is fatal."""
    try:
        subprocess.run(  # noqa: S603 (path we just wrote)
            [str(path), "-h"], capture_output=True, timeout=15, check=False
        )
    except OSError as exc:
        raise EngineInstallError(
            f"the downloaded engine at {path} will not run ({exc}). This usually "
            "means the wrong architecture was fetched. Build from source instead."
        ) from exc


def install_engine(
    console: Console | None = None,
    *,
    tag: str | None = None,
    dest_dir: str | None = None,
    system: str | None = None,
    machine: str | None = None,
) -> Path:
    """Download the prebuilt engine for this platform and return its path.

    ``system``/``machine`` default to the current platform; they are parameters so
    the mapping can be tested without spoofing the interpreter.
    """
    import platform

    console = console or Console()
    asset = _asset_name(system or platform.system(), machine or platform.machine())
    tag = tag or _latest_tag()
    target_dir = Path(dest_dir) if dest_dir else _dest_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    dest = target_dir / _BINARY_NAME

    url = f"https://github.com/{_REPO}/releases/download/{tag}/{asset}"
    console.print(f"[dim]downloading {asset} ({tag}) -> {dest}[/dim]")
    _download(url, dest)
    _make_executable(dest)
    _verify_runs(dest)

    console.print(f"[green]installed[/green] banshee-engine {tag} -> {dest}")
    if not shutil.which("banshee-engine"):
        console.print(
            f"[yellow]note:[/yellow] {target_dir} is not on your PATH. Either add it, "
            f"or set BANSHEE_ENGINE={dest} so `--engine go` finds the binary."
        )
    else:
        console.print("[dim]`--engine go` and `--engine auto` will now use it.[/dim]")
    return dest
