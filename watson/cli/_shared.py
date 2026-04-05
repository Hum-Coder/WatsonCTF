"""
Shared CLI singletons: console instance and banner printer.
"""
from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from watson import __version__
from watson.quotes import get_opening

console = Console()


def _print_banner() -> None:
    """Print the Watson startup banner."""
    quote = get_opening()
    banner_text = Text()
    banner_text.append(" W A T S O N \n", style="bold white")
    banner_text.append(" Forensics CTF Solver\n", style="dim white")
    banner_text.append(f" v{__version__}\n\n", style="dim")
    banner_text.append(f' "{quote}"\n', style="italic dim white")
    banner_text.append("                      — Dr. J.H. Watson", style="dim")

    console.print(
        Panel(
            banner_text,
            border_style="white",
            box=box.DOUBLE_EDGE,
            padding=(0, 2),
        )
    )
    console.print()
