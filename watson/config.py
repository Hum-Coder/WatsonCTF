"""
Watson user configuration.

Manages ~/.config/watson/watson.cfg — a plain INI/CFG file editable
in any text editor. The old modules.json is migrated automatically on
first load if it exists.

Precedence: CLI flag > config file > built-in default
"""
from __future__ import annotations

import configparser
from pathlib import Path
from typing import List, Optional


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def get_config_dir() -> Path:
    return Path.home() / ".config" / "watson"

def get_config_path() -> Path:
    return get_config_dir() / "watson.cfg"

def _legacy_modules_path() -> Path:
    return get_config_dir() / "modules.json"


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULTS = {
    "core": {
        "default_depth":    "3",
        "default_max_files": "25",
        "aggressive":       "false",
        "extract_dir":      "",
        "verbose":          "false",
    },
    "modules": {
        "enabled": "core,images,containers",
    },
    "output": {
        "theme": "true",
        "color": "true",
    },
    "triage": {
        "max_depth":     "3",
        "max_files":     "25",
        "entropy_boost": "true",
    },
    "flags": {
        "extra_patterns": "",
    },
}


# ---------------------------------------------------------------------------
# Load / save
# ---------------------------------------------------------------------------

def _make_parser() -> configparser.ConfigParser:
    """Return a ConfigParser pre-loaded with defaults."""
    parser = configparser.ConfigParser()
    for section, values in DEFAULTS.items():
        parser[section] = values
    return parser


def load() -> configparser.ConfigParser:
    """
    Load watson.cfg. Creates it from defaults if absent.
    Migrates modules.json if it exists and watson.cfg does not.
    """
    parser = _make_parser()
    cfg_path = get_config_path()

    if not cfg_path.exists():
        _migrate_legacy(parser)
        save(parser)
    else:
        parser.read(cfg_path, encoding="utf-8")

    # Always ensure core is in enabled modules
    enabled = get_enabled_modules(parser)
    if "core" not in enabled:
        enabled.insert(0, "core")
        parser["modules"]["enabled"] = ",".join(enabled)

    return parser


def save(parser: configparser.ConfigParser) -> None:
    """Write the config to disk."""
    cfg_path = get_config_path()
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    with cfg_path.open("w", encoding="utf-8") as fh:
        fh.write(_HEADER)
        parser.write(fh)


def _migrate_legacy(parser: configparser.ConfigParser) -> None:
    """Pull enabled modules out of the old modules.json if present."""
    legacy = _legacy_modules_path()
    if not legacy.exists():
        return
    try:
        import json
        data = json.loads(legacy.read_text(encoding="utf-8"))
        modules = data.get("enabled_modules", [])
        if modules and isinstance(modules, list):
            parser["modules"]["enabled"] = ",".join(modules)
    except Exception:
        pass


_HEADER = """\
# Watson configuration file
# Edit this file directly or use: watson config set <section.key> <value>
#
# Precedence: CLI flag > this file > built-in default
#
# Sections:
#   [core]     — examine defaults (depth, max_files, extract_dir, verbose)
#   [modules]  — which modules are enabled by default
#   [output]   — theme and colour settings
#   [triage]   — file prioritisation settings
#   [flags]    — extra CTF flag patterns (comma-separated regexes)

"""


# ---------------------------------------------------------------------------
# Typed getters
# ---------------------------------------------------------------------------

def get_int(parser: configparser.ConfigParser, section: str, key: str) -> int:
    try:
        return parser.getint(section, key)
    except (ValueError, configparser.Error):
        return int(DEFAULTS[section][key])


def get_bool(parser: configparser.ConfigParser, section: str, key: str) -> bool:
    try:
        return parser.getboolean(section, key)
    except (ValueError, configparser.Error):
        return DEFAULTS[section][key].lower() == "true"


def get_str(parser: configparser.ConfigParser, section: str, key: str) -> str:
    try:
        return parser.get(section, key)
    except configparser.Error:
        return DEFAULTS[section].get(key, "")


def get_list(parser: configparser.ConfigParser, section: str, key: str) -> List[str]:
    raw = get_str(parser, section, key)
    return [v.strip() for v in raw.split(",") if v.strip()]


# ---------------------------------------------------------------------------
# Module helpers (backwards-compatible API used by examiner + CLI)
# ---------------------------------------------------------------------------

def get_enabled_modules(parser: Optional[configparser.ConfigParser] = None) -> List[str]:
    if parser is None:
        parser = load()
    modules = get_list(parser, "modules", "enabled")
    if "core" not in modules:
        modules.insert(0, "core")
    return modules


def enable_module(name: str) -> None:
    parser = load()
    enabled = get_enabled_modules(parser)
    if name not in enabled:
        enabled.append(name)
    parser["modules"]["enabled"] = ",".join(enabled)
    save(parser)


def disable_module(name: str) -> None:
    if name == "core":
        raise ValueError("The 'core' module cannot be disabled.")
    parser = load()
    enabled = [m for m in get_enabled_modules(parser) if m != name]
    parser["modules"]["enabled"] = ",".join(enabled)
    save(parser)


def is_enabled(name: str) -> bool:
    return name in get_enabled_modules()


def set_value(section: str, key: str, value: str) -> None:
    """Set a config value and save. Creates section if needed."""
    parser = load()
    if section not in parser:
        parser[section] = {}
    parser[section][key] = value
    save(parser)


def reset() -> None:
    """Reset config to defaults (preserves enabled modules)."""
    enabled = get_enabled_modules()
    parser = _make_parser()
    parser["modules"]["enabled"] = ",".join(enabled)
    save(parser)
