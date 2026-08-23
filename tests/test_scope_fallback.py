"""The packaged default scope must let an installed `banshee` run from any
directory. Without it, the first command after `pipx install banshee` fails with
"scope file not found" because the wheel ships no config/ tree. These tests pin
that the fallback resolves — and that an explicitly-passed missing path still
fails loudly rather than being silently swapped for the default.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import yaml
from rich.console import Console

from scanner.cli import _DEFAULT_SCOPE_FILE, _resolve_scope_file
from scanner.core.scope import ScopeGuard

_QUIET_CONSOLE = Console(quiet=True)


def test_packaged_default_scope_is_shipped_and_valid() -> None:
    packaged = files("scanner").joinpath("data", "default_scope.yaml")
    assert packaged.is_file(), "default scope not packaged inside scanner/"
    data = yaml.safe_load(packaged.read_text(encoding="utf-8"))
    assert data["allowlist"], "packaged scope must have a non-empty allowlist"
    # It must actually load through the real guard and enforce RFC1918 scope.
    guard = ScopeGuard.from_file(str(packaged))
    assert guard.is_in_scope("192.168.1.10")
    assert not guard.is_in_scope("8.8.8.8")


def test_missing_default_scope_falls_back_to_packaged(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)  # no config/ here, mimicking an installed run
    resolved = _resolve_scope_file(_DEFAULT_SCOPE_FILE, _QUIET_CONSOLE, quiet=True)
    assert Path(resolved).is_file()
    assert Path(resolved).name == "default_scope.yaml"


def test_explicit_missing_scope_is_not_silently_replaced(tmp_path: Path) -> None:
    explicit = str(tmp_path / "my-engagement.yaml")  # user asked for this exact file
    resolved = _resolve_scope_file(explicit, _QUIET_CONSOLE, quiet=True)
    assert resolved == explicit  # left as-is, so the CLI fails loudly with their path
