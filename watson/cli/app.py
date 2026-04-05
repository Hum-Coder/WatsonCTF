"""
Typer application — registers all commands and the main callback.
"""
from __future__ import annotations

import sys

import typer

from watson import __version__
from watson.cli._shared import console
from watson.cli.examine import examine
from watson.cli.doctor import doctor
from watson.cli.modules import modules_app

app = typer.Typer(
    name="watson",
    help="Watson — A forensics CTF solver. 'Elementary, my dear user.'",
    add_completion=False,
    no_args_is_help=True,
)

app.command("examine")(examine)
app.command("doctor")(doctor)
app.add_typer(modules_app, name="modules")


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


def _preprocess_argv() -> None:
    """
    Pre-process sys.argv so that `watson <file>` works as a shorthand
    for `watson examine <file>`.

    If the first positional argument is not a known subcommand and exists
    as a file/directory on disk, insert 'examine' before it.
    """
    from pathlib import Path

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
