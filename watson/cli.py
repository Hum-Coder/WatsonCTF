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
    Check Watson's capabilities — tools, Python packages, and system dependencies.
    """
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

    # --- System tools ---
    system_tools = [
        ("binwalk",   "Firmware/file carving",          "apt install binwalk"),
        ("foremost",  "File carving",                    "apt install foremost"),
        ("mmls",      "Disk partition analysis (TSK)",   "apt install sleuthkit"),
        ("fls",       "Filesystem listing (TSK)",        "apt install sleuthkit"),
        ("icat",      "File recovery (TSK)",             "apt install sleuthkit"),
        ("steghide",  "Steganography extraction",        "apt install steghide"),
        ("exiftool",  "EXIF metadata",                   "apt install libimage-exiftool-perl"),
        ("qemu-img",  "Disk image conversion",           "apt install qemu-utils"),
        ("pdfinfo",   "PDF metadata",                    "apt install poppler-utils"),
        ("ffmpeg",    "Audio conversion",                "apt install ffmpeg"),
        ("mount",     "Filesystem mounting",             "pre-installed on Linux"),
    ]

    tool_table = Table(
        title="System Tools",
        box=box.SIMPLE_HEAD,
        border_style="dim",
        show_header=True,
        header_style="bold white",
    )
    tool_table.add_column("Tool",         width=14)
    tool_table.add_column("Purpose",      width=30)
    tool_table.add_column("Status",       width=10)
    tool_table.add_column("Install hint", width=40, overflow="fold")

    for tool, purpose, install in system_tools:
        found = shutil.which(tool) is not None
        status = "[bold green]  OK [/bold green]" if found else "[bold red] MISS[/bold red]"
        hint = "" if found else f"[dim]{install}[/dim]"
        tool_table.add_row(tool, purpose, status, hint)

    console.print(tool_table)
    console.print()

    # --- Python packages ---
    python_pkgs = [
        ("magic",    "python-magic",  "MIME type detection",        "pip install python-magic"),
        ("PIL",      "Pillow",        "Image analysis",             "pip install Pillow"),
        ("mutagen",  "mutagen",       "Audio metadata",             "pip install mutagen"),
        ("pypdf",    "pypdf",         "PDF analysis",               "pip install pypdf"),
        ("scapy",    "scapy",         "Network forensics",          "pip install scapy"),
        ("scipy",    "scipy",         "Spectrogram generation",     "pip install scipy"),
        ("numpy",    "numpy",         "Numerical processing",       "pip install numpy"),
        ("pytsk3",   "pytsk3",        "Disk image analysis (TSK)",  "pip install pytsk3"),
        ("yaml",     "pyyaml",        "YAML config support",        "pip install pyyaml"),
        ("typer",    "typer",         "CLI framework",              "pip install typer"),
        ("rich",     "rich",          "Rich terminal output",       "pip install rich"),
    ]

    pkg_table = Table(
        title="Python Packages",
        box=box.SIMPLE_HEAD,
        border_style="dim",
        show_header=True,
        header_style="bold white",
    )
    pkg_table.add_column("Import",   width=12)
    pkg_table.add_column("Package",  width=12)
    pkg_table.add_column("Purpose",  width=30)
    pkg_table.add_column("Status",   width=10)
    pkg_table.add_column("Install",  width=30, overflow="fold")

    for import_name, pkg_name, purpose, install in python_pkgs:
        try:
            __import__(import_name)
            available = True
        except ImportError:
            available = False

        status = "[bold green]  OK [/bold green]" if available else "[bold red] MISS[/bold red]"
        hint = "" if available else f"[dim]{install}[/dim]"
        pkg_table.add_row(import_name, pkg_name, purpose, status, hint)

    console.print(pkg_table)
    console.print()

    # Summary
    sys_ok = sum(1 for tool, _, _ in system_tools if shutil.which(tool))
    py_ok = 0
    for import_name, *_ in python_pkgs:
        try:
            __import__(import_name)
            py_ok += 1
        except ImportError:
            pass

    total_sys = len(system_tools)
    total_py = len(python_pkgs)

    summary = Text()
    summary.append(f"System tools: {sys_ok}/{total_sys} available\n", style="white")
    summary.append(f"Python pkgs:  {py_ok}/{total_py} available\n\n", style="white")

    if sys_ok == total_sys and py_ok == total_py:
        summary.append("Watson is fully equipped. The game is afoot!\n", style="bold green")
    elif sys_ok >= 3 and py_ok >= 5:
        summary.append("Watson is operational. Some capabilities may be limited.\n", style="bold yellow")
    else:
        summary.append("Watson is running in minimal mode. Install more tools for full capability.\n", style="bold red")

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
    _KNOWN_SUBCOMMANDS = {"examine", "doctor", "--help", "-h", "--version", "-V"}
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
