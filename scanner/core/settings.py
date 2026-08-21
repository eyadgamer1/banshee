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
    """Resolved settings. Every field is read by a real call site."""

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
