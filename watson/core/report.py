"""
Watson Case Report — Rich-based Victorian detective's notebook for the terminal.
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from watson.quotes import get_opening, get_uncertain, get_random


# Confidence colour map
_CONF_COLOUR = {
    "HIGH": "bold red",
    "MED": "bold yellow",
    "LOW": "dim cyan",
}

_CONF_LABEL = {
    "HIGH": "[bold red]● HIGH[/bold red]",
    "MED":  "[bold yellow]◐ MED [/bold yellow]",
    "LOW":  "[dim cyan]○ LOW [/dim cyan]",
}


class CaseReport:
    """Formats and prints Watson investigation output to a Rich Console."""

    def __init__(self, filename: str, console: Optional[Console] = None) -> None:
        self.filename = filename
        self.console = console or Console()
        self._finding_count = 0

    # ------------------------------------------------------------------
    # Case header
    # ------------------------------------------------------------------

    def header(self, filename: str, filesize: int, filetype: str) -> None:
        """Print the opening case header."""
        quote = get_opening()
        size_str = self._human_size(filesize)

        header_text = Text()
        header_text.append("WATSON FORENSIC CASE REPORT\n", style="bold white")
        header_text.append("─" * 50 + "\n", style="dim")
        header_text.append(f"  Subject:  ", style="dim")
        header_text.append(f"{filename}\n", style="bold cyan")
        header_text.append(f"  Size:     ", style="dim")
        header_text.append(f"{size_str}\n", style="white")
        header_text.append(f"  Type:     ", style="dim")
        header_text.append(f"{filetype}\n", style="white")
        header_text.append("─" * 50 + "\n", style="dim")
        header_text.append(f"\n  \"{quote}\"\n", style="italic dim white")
        header_text.append(f"                        — Dr. J.H. Watson\n", style="dim")

        self.console.print(
            Panel(
                header_text,
                title="[bold white][ CASE OPENED ][/bold white]",
                border_style="white",
                box=box.DOUBLE_EDGE,
                padding=(0, 1),
            )
        )
        self.console.print()

    # ------------------------------------------------------------------
    # Section dividers
    # ------------------------------------------------------------------

    def section(self, title: str) -> None:
        """Print a section divider that looks like a notebook entry."""
        self.console.print()
        self.console.print(
            f"[bold white]┌─[ [/bold white][bold cyan]{title}[/bold cyan][bold white] ]{'─' * max(0, 55 - len(title))}┐[/bold white]"
        )

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def finding(
        self,
        technique: str,
        message: str,
        confidence: str,
        extracted: Optional[Path] = None,
    ) -> None:
        """Print a single finding entry."""
        self._finding_count += 1
        conf_label = _CONF_LABEL.get(confidence.upper(), _CONF_LABEL["LOW"])
        conf_colour = _CONF_COLOUR.get(confidence.upper(), "dim")

        self.console.print(
            f"  {conf_label} [dim]{technique}[/dim]"
        )
        self.console.print(f"       [white]{message}[/white]")
        if extracted:
            self.console.print(
                f"       [dim]→ Extracted: [/dim][green]{extracted}[/green]"
            )

    def flag_found(self, flag: str, technique: str) -> None:
        """Print a very prominent flag panel."""
        flag_text = Text()
        flag_text.append("Good heavens — a flag!\n\n", style="bold white")
        flag_text.append(f"  {flag}\n", style="bold bright_green")
        flag_text.append(f"\n  Discovered by: {technique}", style="dim green")

        self.console.print()
        self.console.print(
            Panel(
                flag_text,
                title="[bold bright_green][ FLAG FOUND ][/bold bright_green]",
                border_style="bright_green",
                box=box.DOUBLE_EDGE,
                padding=(1, 2),
            )
        )
        self.console.print()

    # ------------------------------------------------------------------
    # Conclusion
    # ------------------------------------------------------------------

    def conclusion(self, findings: list) -> None:
        """Print the case conclusion summary."""
        high = [f for f in findings if getattr(f, "confidence", "").upper() == "HIGH"]
        med  = [f for f in findings if getattr(f, "confidence", "").upper() == "MED"]
        low  = [f for f in findings if getattr(f, "confidence", "").upper() == "LOW"]
        flags = [f for f in findings if getattr(f, "flag", None)]

        self.console.print()

        # Summary table
        table = Table(
            title="Case Summary",
            box=box.SIMPLE_HEAD,
            border_style="dim",
            show_header=True,
            header_style="bold white",
        )
        table.add_column("Confidence", style="bold", width=12)
        table.add_column("Findings",   justify="right", width=10)

        table.add_row("[bold red]HIGH[/bold red]",   str(len(high)))
        table.add_row("[bold yellow]MED[/bold yellow]",    str(len(med)))
        table.add_row("[dim cyan]LOW[/dim cyan]",     str(len(low)))
        table.add_row("[dim]Flags[/dim]",  f"[bold bright_green]{len(flags)}[/bold bright_green]")

        self.console.print(table)
        self.console.print()

        # Closing remark
        if flags:
            closing = Text()
            closing.append("Elementary.\n\n", style="bold white")
            closing.append("The flags speak for themselves. The case is closed.\n", style="dim white")
            closing.append(f"\n  Found {len(flags)} flag(s): ", style="dim")
            for f in flags:
                closing.append(f"\n    {f.flag}", style="bold bright_green")
        elif high or med:
            quote = get_uncertain()
            closing = Text()
            closing.append(f"\"{quote}\"\n", style="italic white")
            closing.append("                        — Dr. J.H. Watson\n\n", style="dim")
            closing.append(
                "  No flag recovered, but the trail is warm. Follow these leads:\n\n",
                style="white",
            )
        else:
            quote = get_uncertain()
            closing = Text()
            closing.append(f"\"{quote}\"\n", style="italic white")
            closing.append("                        — Dr. J.H. Watson\n\n", style="dim")
            if low:
                closing.append(
                    f"  {len(low)} low-confidence observations recorded. May be worth a look.\n",
                    style="dim white",
                )
            else:
                closing.append(
                    "  No significant findings. The subject appears unremarkable.\n",
                    style="dim white",
                )

        self.console.print(
            Panel(
                closing,
                title="[bold white][ WATSON'S CONCLUSION ][/bold white]",
                border_style="white",
                box=box.ROUNDED,
                padding=(0, 2),
            )
        )

        # Leads panel — non-flag HIGH and MED findings listed explicitly
        leads = [f for f in findings if not getattr(f, "flag", None)
                 and getattr(f, "confidence", "").upper() in ("HIGH", "MED")]
        if leads and not flags:
            self.console.print()
            leads_text = Text()
            for i, f in enumerate(leads, 1):
                conf = getattr(f, "confidence", "MED").upper()
                bullet = "[bold red]●[/bold red]" if conf == "HIGH" else "[bold yellow]◐[/bold yellow]"
                technique = getattr(f, "technique", "unknown")
                message = getattr(f, "message", "")
                extracted = getattr(f, "extracted_files", [])
                leads_text.append(f"  {i}. ", style="dim")
                leads_text.append(f"{message}\n", style="white")
                leads_text.append(f"     technique: {technique}", style="dim")
                if extracted:
                    leads_text.append(f"  →  {extracted[0]}", style="dim green")
                leads_text.append("\n")

            self.console.print(
                Panel(
                    leads_text,
                    title="[bold yellow][ LEADS TO FOLLOW ][/bold yellow]",
                    border_style="yellow",
                    box=box.ROUNDED,
                    padding=(0, 2),
                )
            )

    # ------------------------------------------------------------------
    # Warnings and notices
    # ------------------------------------------------------------------

    def warn(self, msg: str) -> None:
        """Print a yellow warning."""
        self.console.print(f"  [bold yellow]⚠  {msg}[/bold yellow]")

    def capability_missing(self, tool: str, technique: str) -> None:
        """Dim notice that an optional tool is missing."""
        self.console.print(
            f"  [dim]○ [{technique}] '{tool}' not available — technique skipped.[/dim]"
        )

    def info(self, msg: str) -> None:
        """Print an informational message."""
        self.console.print(f"  [dim]{msg}[/dim]")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _human_size(size: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
