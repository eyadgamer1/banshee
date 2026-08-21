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

# Plain-ASCII fallback. A default Windows console is cp1252 and cannot encode the
# block-drawing glyphs above, which raised UnicodeEncodeError before the scan even
# started — on the platform most likely to be running this.
_BANNER_ASCII = r"""
  ____    _    _   _ ____  _   _ _____ _____
 | __ )  / \  | \ | / ___|| | | | ____| ____|
 |  _ \ / _ \ |  \| \___ \| |_| |  _| |  _|
 | |_) / ___ \| |\  |___) |  _  | |___| |___
 |____/_/   \_\_| \_|____/|_| |_|_____|_____|"""

_TAGLINE = "She sees everything you left exposed."
_SUBLINE = "Broad-Area Network Scanner for Host Enumeration and Exposure"


def _encodable(text: str, console: Console) -> bool:
    """True if the console's encoding can represent `text`."""
    encoding = getattr(console.file, "encoding", None) or "utf-8"
    try:
        text.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def print_banner(console: Console, *, quiet: bool = False, silent: bool = False) -> None:
    """Print the startup banner. Suppressed in --quiet and --silent modes."""
    if silent or quiet:
        return

    art = _BANNER if _encodable(_BANNER, console) else _BANNER_ASCII
    banner_text = Text(art, style="bold red")
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
