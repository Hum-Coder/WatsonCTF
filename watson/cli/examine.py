"""
Examine command — inspect a file or directory for CTF clues.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.panel import Panel
from rich.text import Text

from watson.cli._shared import console, _print_banner


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
