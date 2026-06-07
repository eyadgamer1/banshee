"""BANSHEE terminal banner and startup UI."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from scanner import __version__

_BANNER = r"""
  ██████╗  █████╗ ███╗   ██╗███████╗██╗  ██╗███████╗███████╗
  ██╔══██╗██╔══██╗████╗  ██║██╔════╝██║  ██║██╔════╝██╔════╝
  ██████╔╝███████║██╔██╗ ██║███████╗███████║█████╗  █████╗
  ██╔══██╗██╔══██║██║╚██╗██║╚════██║██╔══██║██╔══╝  ██╔══╝
  ██████╔╝██║  ██║██║ ╚████║███████║██║  ██║███████╗███████╗
  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝"""

_TAGLINE = "She sees everything you left exposed."
_SUBLINE = "Broad-Area Network Scanner for Host Enumeration and Exposure"


def print_banner(console: Console, *, quiet: bool = False, silent: bool = False) -> None:
    """Print the startup banner. Suppressed in --quiet and --silent modes."""
    if silent or quiet:
        return

    banner_text = Text(_BANNER, style="bold red")
    tagline = Text(f"\n  {_TAGLINE}", style="italic dim red")
    subline = Text(f"\n  {_SUBLINE}  |  v{__version__}", style="dim")

    combined = banner_text + tagline + subline

    console.print(
        Panel(
            combined,
            border_style="red",
            padding=(0, 1),
        )
    )
    console.print()
