"""`banshee install-engine` — platform mapping and CLI wiring, no network."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from scanner import engine_install
from scanner.cli import install_app
from scanner.engine_install import EngineInstallError, _asset_name, _dest_dir

runner = CliRunner()


@pytest.mark.parametrize(
    ("system", "machine", "asset"),
    [
        ("Linux", "x86_64", "banshee-engine-linux-amd64"),
        ("Linux", "aarch64", "banshee-engine-linux-arm64"),
        ("Darwin", "arm64", "banshee-engine-darwin-arm64"),
        ("Darwin", "x86_64", "banshee-engine-darwin-amd64"),
        ("Windows", "AMD64", "banshee-engine-windows-amd64.exe"),
    ],
)
def test_asset_name_maps_known_platforms(system, machine, asset):
    assert _asset_name(system, machine) == asset


def test_asset_name_rejects_unsupported_platform():
    with pytest.raises(EngineInstallError):
        _asset_name("Plan9", "sparc")


def test_dest_dir_prefers_the_banshee_bin_dir(monkeypatch):
    monkeypatch.setattr(engine_install.shutil, "which", lambda _n: "/opt/tools/bin/banshee")
    assert _dest_dir().name == "bin"


def test_install_engine_cmd_passes_options_through(monkeypatch):
    seen = {}

    def _stub(console, *, tag, dest_dir):
        seen["tag"], seen["dir"] = tag, dest_dir

    monkeypatch.setattr("scanner.cli.install_engine", _stub)
    r = runner.invoke(install_app, ["--tag", "v1.3.0", "--dir", "/tmp/x"])
    assert r.exit_code == 0, r.output
    assert seen == {"tag": "v1.3.0", "dir": "/tmp/x"}


def test_install_engine_cmd_reports_error_as_exit_1(monkeypatch):
    def _boom(console, *, tag, dest_dir):
        raise EngineInstallError("no prebuilt engine for Plan9/sparc")

    monkeypatch.setattr("scanner.cli.install_engine", _boom)
    r = runner.invoke(install_app, [])
    assert r.exit_code == 1, r.output
    assert "error" in r.output.lower()
