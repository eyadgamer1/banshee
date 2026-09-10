"""config/settings.toml loader — defaults beneath CLI flags.

Only keys that some module actually reads live here. A setting that nothing
consumes is worse than no setting at all: it silently lies about what the run
will do. If you add a key to settings.toml, wire it here in the same commit.
"""

from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_SETTINGS_PATH = Path("config/settings.toml")

_DEFAULT_LLM_MODEL = "llama3"
_DEFAULT_LLM_URL = "http://localhost:11434"
_DEFAULT_LLM_TIMEOUT = 60


@dataclass(frozen=True)
class Settings:
    """Resolved settings. Every field is read by a real call site.

    `llm_*` are read by scanner/llm/{react,report}.py. `db_path` is read by
    `resolve_db_path()` below, which is the function the CLI must use to resolve
    `--db` — passing the raw `--db` value straight into ScanConfig is what made the
    documented `[store].db_path` key a silent no-op.
    """

    llm_model: str = _DEFAULT_LLM_MODEL
    llm_base_url: str = _DEFAULT_LLM_URL
    llm_timeout_seconds: int = _DEFAULT_LLM_TIMEOUT
    db_path: str | None = None

    @property
    def ollama_chat_url(self) -> str:
        return f"{self.llm_base_url.rstrip('/')}/api/chat"


def load_settings(path: str | Path | None = None) -> Settings:
    """Read settings.toml. A missing or malformed file yields defaults."""
    p = Path(path) if path is not None else DEFAULT_SETTINGS_PATH
    if not p.is_file():
        return Settings()
    try:
        with p.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        log.warning("Ignoring unreadable settings file %s: %s", p, exc)
        return Settings()

    llm = data.get("llm", {})
    store = data.get("store", {})
    return Settings(
        llm_model=str(llm.get("model", _DEFAULT_LLM_MODEL)),
        llm_base_url=str(llm.get("base_url", _DEFAULT_LLM_URL)),
        llm_timeout_seconds=int(llm.get("timeout_seconds", _DEFAULT_LLM_TIMEOUT)),
        db_path=str(store["db_path"]) if store.get("db_path") else None,
    )


def resolve_db_path(cli_value: str | None, settings: Settings | None = None) -> str | None:
    """Resolve the effective SQLite path: --db wins, else `[store].db_path`, else None.

    This is the call site that makes `Settings.db_path` real. Without it the key was
    documented in settings.toml ("Default for --db") but read by nothing, so a user who
    configured it and omitted --db silently got no persistence at all.

    The parent directory is created here because the shipped default lives under
    `output/`: `ScanStore` opens the path directly, and sqlite raising "unable to open
    database file" would abort a scan over a directory we can make ourselves. If it
    cannot be created, persistence is disabled with a warning rather than exploding.
    """
    if cli_value:
        return cli_value
    configured = (settings if settings is not None else load_settings()).db_path
    if not configured:
        return None
    parent = Path(configured).expanduser().parent
    try:
        if str(parent):
            parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        log.warning(
            "Ignoring [store].db_path %s — cannot create %s: %s", configured, parent, exc
        )
        return None
    return configured
