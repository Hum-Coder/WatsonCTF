"""
Modules subcommand group — list, enable, disable, install.
"""
from __future__ import annotations

import typer
from rich import box
from rich.table import Table

from watson.cli._shared import console

modules_app = typer.Typer(help="Manage Watson modules.")


@modules_app.command("list")
def modules_list() -> None:
    """List all Watson modules and their status."""
    import watson.config as _config
    import watson.modules as _modules

    table = Table(
        title="Watson Modules",
        box=box.SIMPLE_HEAD,
        border_style="dim",
        show_header=True,
        header_style="bold white",
    )
    table.add_column("Name",        width=12)
    table.add_column("Description", width=45)
    table.add_column("Enabled",     width=9)
    table.add_column("Available",   width=10)
    table.add_column("Missing deps", width=40, overflow="fold")

    for mod_name, mod in _modules.MODULES.items():
        enabled = _config.is_enabled(mod_name)
        available = mod.is_available()
        enabled_str  = "[bold green]  yes [/bold green]" if enabled  else "[dim]  no [/dim]"
        avail_str    = "[bold green]  yes [/bold green]" if available else "[bold red]  no [/bold red]"

        missing_parts = []
        for pkg in mod.missing_python():
            missing_parts.append(f"pip:{pkg}")
        for tool in mod.missing_system():
            missing_parts.append(f"sys:{tool}")
        missing_str = ", ".join(missing_parts) if missing_parts else "[dim]—[/dim]"

        table.add_row(mod_name, mod.description, enabled_str, avail_str, missing_str)

    console.print()
    console.print(table)
    console.print()


@modules_app.command("enable")
def modules_enable(
    name: str = typer.Argument(..., help="Module name to enable"),
) -> None:
    """Enable a Watson module."""
    import watson.config as _config
    import watson.modules as _modules

    if name not in _modules.MODULES:
        console.print(f"[bold red]Unknown module: {name}[/bold red]")
        console.print(f"Available modules: {', '.join(_modules.MODULES.keys())}")
        raise typer.Exit(1)

    _config.enable_module(name)
    console.print(f"[bold green]Module '{name}' enabled.[/bold green]")


@modules_app.command("disable")
def modules_disable(
    name: str = typer.Argument(..., help="Module name to disable"),
) -> None:
    """Disable a Watson module."""
    import watson.config as _config
    import watson.modules as _modules

    if name not in _modules.MODULES:
        console.print(f"[bold red]Unknown module: {name}[/bold red]")
        console.print(f"Available modules: {', '.join(_modules.MODULES.keys())}")
        raise typer.Exit(1)

    try:
        _config.disable_module(name)
        console.print(f"[bold yellow]Module '{name}' disabled.[/bold yellow]")
    except ValueError as e:
        console.print(f"[bold red]{e}[/bold red]")
        raise typer.Exit(1)


@modules_app.command("install")
def modules_install(
    name: str = typer.Argument(..., help="Module name to install dependencies for"),
) -> None:
    """Show the install command for a Watson module's dependencies."""
    import watson.modules as _modules

    if name not in _modules.MODULES:
        console.print(f"[bold red]Unknown module: {name}[/bold red]")
        console.print(f"Available modules: {', '.join(_modules.MODULES.keys())}")
        raise typer.Exit(1)

    mod = _modules.MODULES[name]
    missing_py  = mod.missing_python()
    missing_sys = mod.missing_system()

    console.print()
    console.print(f"[bold white]Install instructions for module:[/bold white] [bold cyan]{name}[/bold cyan]")
    console.print()

    if not missing_py and not missing_sys:
        console.print(f"[bold green]Module '{name}' is fully available — nothing to install.[/bold green]")
        console.print()
        return

    if missing_py:
        console.print("[bold white]Python packages:[/bold white]")
        console.print(f"  [green]pip install {' '.join(missing_py)}[/green]")
        console.print()

    if missing_sys:
        console.print("[bold white]System packages:[/bold white]")
        # Detect OS type for the hint
        import shutil as _shutil
        if _shutil.which("apt-get"):
            os_type = "apt"
        elif _shutil.which("dnf"):
            os_type = "dnf"
        elif _shutil.which("yum"):
            os_type = "yum"
        elif _shutil.which("pacman"):
            os_type = "pacman"
        elif _shutil.which("brew"):
            os_type = "brew"
        else:
            os_type = "apt"

        pkgs = mod.install_cmd(os_type)
        if pkgs:
            if os_type == "apt":
                console.print(f"  [green]sudo apt-get install -y {' '.join(pkgs)}[/green]")
            elif os_type in ("dnf", "yum"):
                console.print(f"  [green]sudo {os_type} install -y {' '.join(pkgs)}[/green]")
            elif os_type == "pacman":
                console.print(f"  [green]sudo pacman -S --needed {' '.join(pkgs)}[/green]")
            elif os_type == "brew":
                console.print(f"  [green]brew install {' '.join(pkgs)}[/green]")
        else:
            console.print(f"  [dim]Missing tools: {', '.join(missing_sys)} — install manually for your OS[/dim]")
        console.print()
