"""
Config command — view and edit watson.cfg from the CLI.
"""
from __future__ import annotations

from typing import Optional

import typer
from rich import box
from rich.table import Table
from rich.text import Text

from watson.cli._shared import console

config_app = typer.Typer(help="View and edit Watson configuration.")


@config_app.command("show")
def config_show() -> None:
    """Print the current configuration."""
    import watson.config as _config
    cfg = _config.load()
    path = _config.get_config_path()

    console.print(f"\n[dim]Config file: {path}[/dim]\n")

    for section in cfg.sections():
        table = Table(
            title=f"[{section}]",
            box=box.SIMPLE_HEAD,
            border_style="dim",
            show_header=True,
            header_style="bold white",
            title_style="bold cyan",
            title_justify="left",
        )
        table.add_column("Key",   width=20)
        table.add_column("Value", width=50)
        table.add_column("Default", width=20, style="dim")

        for key, value in cfg.items(section):
            default = _config.DEFAULTS.get(section, {}).get(key, "")
            style = "" if value == default else "bold white"
            table.add_row(key, Text(value or "(empty)", style=style), default or "(empty)")

        console.print(table)
        console.print()


@config_app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Key in section.key format, e.g. core.default_depth"),
    value: str = typer.Argument(..., help="Value to set"),
) -> None:
    """Set a config value. Use section.key format, e.g. core.default_depth 5"""
    import watson.config as _config

    if "." not in key:
        console.print(f"[bold red]Error:[/bold red] Key must be in section.key format (e.g. core.default_depth)")
        raise typer.Exit(1)

    section, k = key.split(".", 1)
    if section not in _config.DEFAULTS:
        console.print(f"[bold red]Unknown section:[/bold red] '{section}'. Valid sections: {', '.join(_config.DEFAULTS)}")
        raise typer.Exit(1)
    if k not in _config.DEFAULTS.get(section, {}):
        console.print(f"[bold red]Unknown key:[/bold red] '{k}' in [{section}]. Valid keys: {', '.join(_config.DEFAULTS[section])}")
        raise typer.Exit(1)

    _config.set_value(section, k, value)
    console.print(f"[green]✓[/green] [white]{section}[/white].[cyan]{k}[/cyan] = [bold]{value}[/bold]")


@config_app.command("get")
def config_get(
    key: str = typer.Argument(..., help="Key in section.key format, e.g. core.default_depth"),
) -> None:
    """Get a config value."""
    import watson.config as _config

    if "." not in key:
        console.print(f"[bold red]Error:[/bold red] Use section.key format (e.g. core.default_depth)")
        raise typer.Exit(1)

    section, k = key.split(".", 1)
    cfg = _config.load()
    try:
        value = cfg.get(section, k)
        console.print(f"[white]{section}[/white].[cyan]{k}[/cyan] = [bold]{value}[/bold]")
    except Exception:
        console.print(f"[bold red]Not found:[/bold red] {key}")
        raise typer.Exit(1)


@config_app.command("reset")
def config_reset(
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
) -> None:
    """Reset all settings to defaults (preserves enabled modules)."""
    import watson.config as _config

    if not confirm:
        typer.confirm("Reset all config to defaults (modules will be preserved)?", abort=True)

    _config.reset()
    console.print(f"[green]✓[/green] Config reset to defaults. Modules preserved.")
    console.print(f"[dim]Config file: {_config.get_config_path()}[/dim]")


@config_app.command("path")
def config_path() -> None:
    """Print the path to the config file."""
    import watson.config as _config
    console.print(str(_config.get_config_path()))
