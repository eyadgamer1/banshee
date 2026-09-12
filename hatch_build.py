"""Hatchling build hook: compile the Go engine and bundle it into the wheel.

Why this exists: `banshee install-engine` fetched a prebuilt binary from GitHub
Releases, but that release tag can lag behind whatever git commit pip/uv just
built the Python wrapper from. When they disagree on a flag (engine_go.py
started passing `-watch-stdin` before a release was cut with that flag), the
engine binary rejects it and dies instantly — every scan silently reports 0
hosts. See CHANGELOG for the incident.

This hook removes the two-step, two-version install entirely: `pip install`/
`uv tool install` now builds `banshee-engine` from the *same checkout* as the
Python code, right here at wheel-build time, and packs the resulting binary
into the wheel as `scanner/data/banshee-engine[.exe]`. `engine_go.find_engine()`
prefers that bundled copy over anything on PATH, so Python and Go are always
the same commit — one install, no separate engine step, no version drift.

Go absent at build time (no toolchain, or an sdist/build env without the
`engine/` source tree) is not fatal: the hook warns and skips bundling, the
wheel builds pure-Python, and `--engine auto`/`--engine python` still work.
Set BANSHEE_SKIP_GO_BUILD=1 to force that path deliberately (e.g. fast CI
builds that don't need the engine).
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class GoEngineBuildHook(BuildHookInterface):
    PLUGIN_NAME = "go-engine"

    def initialize(self, version: str, build_data: dict) -> None:
        if os.environ.get("BANSHEE_SKIP_GO_BUILD"):
            self.app.display_info("BANSHEE_SKIP_GO_BUILD set — building Python-only wheel")
            return

        go = shutil.which("go")
        if not go:
            self.app.display_warning(
                "go toolchain not found — building Python-only wheel. "
                "Install Go and reinstall for the bundled engine, or fetch one "
                "later with `banshee install-engine`."
            )
            return

        engine_dir = Path(self.root) / "engine"
        if not (engine_dir / "go.mod").is_file():
            self.app.display_warning(
                "engine/ source not present in this build tree — building Python-only wheel."
            )
            return

        binary_name = "banshee-engine.exe" if os.name == "nt" else "banshee-engine"
        out_path = engine_dir / binary_name
        try:
            subprocess.run(
                [go, "build", "-o", str(out_path), "./cmd/banshee-engine"],
                cwd=str(engine_dir),
                check=True,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            stderr = exc.stderr if isinstance(exc, subprocess.CalledProcessError) else str(exc)
            self.app.display_warning(
                f"go build failed — building Python-only wheel instead: {stderr}"
            )
            return

        # force_include merges with the static [tool.hatch.build...force-include]
        # table in pyproject.toml; this is the dynamic half for a file that only
        # exists once this hook has run.
        build_data.setdefault("force_include", {})[str(out_path)] = f"scanner/data/{binary_name}"
        # A native binary is now part of the payload — don't tag this an "any"
        # pure-Python wheel.
        build_data["pure_python"] = False
        build_data["infer_tag"] = True

        self.app.display_info(
            f"bundled banshee-engine ({platform.system()}/{platform.machine()}) "
            f"-> scanner/data/{binary_name}"
        )
