"""
Watson user configuration.

Manages ~/.config/watson/modules.json to persist enabled module selections.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

DEFAULT_ENABLED: List[str] = ["core", "images", "containers"]


def get_config_path() -> Path:
    """Return the path to the Watson config file."""
    return Path.home() / ".config" / "watson" / "modules.json"


def load() -> dict:
    """
    Load the Watson config from disk.
    Returns {"enabled_modules": [...]}
    If the file doesn't exist, returns the default config.
    """
    config_path = get_config_path()
    if not config_path.exists():
        return {"enabled_modules": list(DEFAULT_ENABLED)}
    try:
        with config_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return {"enabled_modules": list(DEFAULT_ENABLED)}
        if "enabled_modules" not in data or not isinstance(data["enabled_modules"], list):
            data["enabled_modules"] = list(DEFAULT_ENABLED)
        return data
    except Exception:
        return {"enabled_modules": list(DEFAULT_ENABLED)}


def save(config: dict) -> None:
    """Save the Watson config to disk."""
    config_path = get_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with config_path.open("w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2)


def get_enabled_modules() -> List[str]:
    """
    Return the list of enabled modules.
    Always includes "core" even if missing from the config file.
    """
    config = load()
    enabled = list(config.get("enabled_modules", DEFAULT_ENABLED))
    if "core" not in enabled:
        enabled.insert(0, "core")
    return enabled


def enable_module(name: str) -> None:
    """Add a module to the enabled list and save."""
    config = load()
    enabled = list(config.get("enabled_modules", DEFAULT_ENABLED))
    if name not in enabled:
        enabled.append(name)
    config["enabled_modules"] = enabled
    save(config)


def disable_module(name: str) -> None:
    """
    Remove a module from the enabled list and save.
    Refuses to disable "core".
    """
    if name == "core":
        raise ValueError("The 'core' module is always on and cannot be disabled.")
    config = load()
    enabled = list(config.get("enabled_modules", DEFAULT_ENABLED))
    enabled = [m for m in enabled if m != name]
    config["enabled_modules"] = enabled
    save(config)


def is_enabled(name: str) -> bool:
    """Return True if the given module is in the enabled list."""
    return name in get_enabled_modules()
