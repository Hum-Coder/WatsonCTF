"""
Watson CLI — the primary entry point.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from watson import __version__
from watson.quotes import get_opening, get_random

app = typer.Typer(
    name="watson",
    help="Watson — A forensics CTF solver. 'Elementary, my dear user.'",
    add_completion=False,
    no_args_is_help=True,
)

modules_app = typer.Typer(help="Manage Watson modules.")
app.add_typer(modules_app, name="modules")


# ------------------------------------------------------------------
# modules subcommands
# ------------------------------------------------------------------

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


console = Console()


# ------------------------------------------------------------------
# Shared banner / startup
# ------------------------------------------------------------------

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


# ------------------------------------------------------------------
# examine command
# ------------------------------------------------------------------

@app.command("examine")
def examine(
    target: Path = typer.Argument(..., help="File or directory to examine.", exists=True),
    depth: int = typer.Option(3, "--depth", "-d", help="Maximum recursion depth."),
    max_files: int = typer.Option(25, "--max-files", "-n", help="Maximum number of files to examine."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output."),
    extract_dir: Optional[Path] = typer.Option(None, "--extract-dir", "-o", help="Directory to store extracted files."),
    aggressive: bool = typer.Option(False, "--aggressive", "-a", help="Aggressive mode: depth=6, max-files=100."),
    modules: Optional[str] = typer.Option(None, "--modules", "-m", help="Comma-separated modules to use, e.g. core,images,disk"),
    skip: Optional[str] = typer.Option(None, "--skip", "-s", help="Comma-separated modules to skip for this run"),
) -> None:
    """
    Examine a file or directory for CTF clues.
    Watson will apply all relevant forensics techniques.
    """
    import watson.config as _config
    from watson.core.report import CaseReport
    from watson.core.triage import TriageQueue
    from watson.core.examiner import Examiner

    _print_banner()

    if aggressive:
        depth = 6
        max_files = 100
        console.print("[bold yellow]Aggressive mode enabled — depth=6, max-files=100[/bold yellow]")
        console.print()

    # Resolve enabled modules for this run
    if modules is not None:
        selected = [m.strip() for m in modules.split(",") if m.strip()]
        if "core" not in selected:
            selected.insert(0, "core")
        resolved_modules: Optional[list] = selected
    elif skip is not None:
        skipped = {m.strip() for m in skip.split(",") if m.strip()}
        resolved_modules = [m for m in _config.get_enabled_modules() if m not in skipped]
        if "core" not in resolved_modules:
            resolved_modules.insert(0, "core")
    else:
        resolved_modules = None  # examiner will read from config

    # Resolve target
    target = target.resolve()

    # Set up extract dir
    import tempfile
    _cleanup_extract_dir = False
    if extract_dir is None:
        extract_dir = Path(tempfile.mkdtemp(prefix="watson_extract_"))
        _cleanup_extract_dir = True
    else:
        extract_dir.mkdir(parents=True, exist_ok=True)

    # Determine file info for header
    if target.is_file():
        filename = target.name
        filesize = target.stat().st_size
        filetype = _detect_mime(target)
    else:
        filename = str(target)
        filesize = sum(f.stat().st_size for f in target.rglob("*") if f.is_file())
        filetype = "directory"

    # Set up report
    report = CaseReport(filename=filename, console=console)
    report.header(filename=filename, filesize=filesize, filetype=filetype)

    # Set up triage
    triage = TriageQueue(max_depth=depth, max_items=max_files)

    # Run examiner
    examiner = Examiner(report=report, triage=triage, verbose=verbose, extract_dir=extract_dir, enabled_modules=resolved_modules)

    try:
        all_findings = examiner.run(target)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Examination interrupted by user.[/bold yellow]")
        all_findings = examiner._all_findings

    # Conclusion
    report.conclusion(all_findings)

    # Summary of flags
    flags = [f.flag for f in all_findings if f.flag]
    if flags:
        console.print()
        flag_text = Text()
        flag_text.append(f"Watson found {len(flags)} flag(s):\n\n", style="bold white")
        for flag in flags:
            flag_text.append(f"  {flag}\n", style="bold bright_green")

        console.print(
            Panel(
                flag_text,
                title="[bold bright_green][ CASE CLOSED — FLAGS RECOVERED ][/bold bright_green]",
                border_style="bright_green",
                box=box.DOUBLE_EDGE,
                padding=(1, 2),
            )
        )

    # Cleanup temp extract dir
    if _cleanup_extract_dir and extract_dir.exists():
        import shutil as _shutil
        try:
            _shutil.rmtree(str(extract_dir), ignore_errors=True)
        except Exception:
            pass


# ------------------------------------------------------------------
# doctor command
# ------------------------------------------------------------------

@app.command("doctor")
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


# ------------------------------------------------------------------
# Default: accept a file as first arg (shorthand for examine)
# ------------------------------------------------------------------

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-V", help="Show version and exit."),
) -> None:
    """
    Watson — A forensics CTF solver CLI.

    Pass a file directly to examine it, or use a subcommand.
    """
    if version:
        console.print(f"watson-ctf v{__version__}")
        raise typer.Exit()

    if ctx.invoked_subcommand is not None:
        return

    console.print(ctx.get_help())
    raise typer.Exit()


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _detect_mime(path: Path) -> str:
    try:
        import magic  # type: ignore
        return magic.from_file(str(path), mime=True)
    except Exception:
        pass
    ext_map = {
        ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
        ".gif": "image/gif", ".pdf": "application/pdf",
        ".zip": "application/zip", ".mp3": "audio/mpeg", ".wav": "audio/wav",
        ".txt": "text/plain",
    }
    return ext_map.get(path.suffix.lower(), "application/octet-stream")


def _preprocess_argv() -> None:
    """
    Pre-process sys.argv so that `watson <file>` works as a shorthand
    for `watson examine <file>`.

    If the first positional argument is not a known subcommand and exists
    as a file/directory on disk, insert 'examine' before it.
    """
    _KNOWN_SUBCOMMANDS = {"examine", "doctor", "modules", "--help", "-h", "--version", "-V"}
    args = sys.argv[1:]
    if not args:
        return
    # Find first non-option argument
    for i, arg in enumerate(args):
        if not arg.startswith("-"):
            if arg not in _KNOWN_SUBCOMMANDS and Path(arg).exists():
                # Insert 'examine' before the file argument
                sys.argv.insert(i + 1, "examine")
            break


def main_entry() -> None:
    """Entry point that handles shorthand file examination."""
    _preprocess_argv()
    app()


if __name__ == "__main__":
    main_entry()
