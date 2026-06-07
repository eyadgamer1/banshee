"""LLM module — local Ollama-backed analysis (D1, D4)."""

from scanner.llm.react import run_react_loop
from scanner.llm.report import generate_report

__all__ = ["run_react_loop", "generate_report"]
