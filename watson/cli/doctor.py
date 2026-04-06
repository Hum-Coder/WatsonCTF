"""
Doctor command — check Watson's capabilities.
"""
from __future__ import annotations

import typer
from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from watson.cli._shared import console
from watson.quotes import get_random


def doctor() -> None:
    """
    Check Watson's capabilities — per-module status, tools, and Python packages.
    """
    import watson.config as _config
    import watson.modules as _modules

    console.print()
    console.print(
        Panel(
            "[bold white]Watson Capability Check[/bold white]\n[dim]Inspecting the available tools...[/dim]",
            border_style="white",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )
    console.print()

    # --- Per-module status table ---
    mod_table = Table(
        title="Module Status",
        box=box.SIMPLE_HEAD,
        border_style="dim",
        show_header=True,
        header_style="bold white",
    )
    mod_table.add_column("Module",      width=12)
    mod_table.add_column("Description", width=42)
    mod_table.add_column("Enabled",     width=9)
    mod_table.add_column("Available",   width=10)
    mod_table.add_column("Missing deps", width=40, overflow="fold")

    modules_ok = 0
    for mod_name, mod in _modules.MODULES.items():
        enabled   = _config.is_enabled(mod_name)
        available = mod.is_available()

        if available:
            modules_ok += 1

        enabled_str = "[bold green]  yes [/bold green]" if enabled  else "[dim]  no [/dim]"
        avail_str   = "[bold green]  yes [/bold green]" if available else "[bold red]  no [/bold red]"

        missing_parts = []
        for pkg in mod.missing_python():
            missing_parts.append(f"pip:{pkg}")
        for tool in mod.missing_system():
            missing_parts.append(f"sys:{tool}")
        missing_str = ", ".join(missing_parts) if missing_parts else "[dim]—[/dim]"

        mod_table.add_row(mod_name, mod.description, enabled_str, avail_str, missing_str)

    console.print(mod_table)
    console.print()

    # Summary
    total_modules = len(_modules.MODULES)
    enabled_modules = _config.get_enabled_modules()
    enabled_count = len(enabled_modules)

    summary = Text()
    summary.append(f"Modules available: {modules_ok}/{total_modules}\n", style="white")
    summary.append(f"Modules enabled:   {enabled_count}/{total_modules}\n\n", style="white")

    if modules_ok == total_modules:
        summary.append("Watson is fully equipped. The game is afoot!\n", style="bold green")
    elif modules_ok >= 3:
        summary.append("Watson is operational. Some capabilities may be limited.\n", style="bold yellow")
    else:
        summary.append("Watson is running in minimal mode. Install more modules for full capability.\n", style="bold red")

    summary.append("\nRun ", style="dim")
    summary.append("watson modules install <name>", style="dim bold")
    summary.append(" to see install commands.\n", style="dim")
    summary.append(f"\n  \"{get_random()}\"\n", style="italic dim white")
    summary.append("                        — Dr. J.H. Watson", style="dim")

    console.print(
        Panel(
            summary,
            title="[bold white][ WATSON DOCTOR REPORT ][/bold white]",
            border_style="white",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )
    console.print()
