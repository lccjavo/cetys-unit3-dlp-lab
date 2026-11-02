"""Shared lab helpers: paths, console setup and JSON security events."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = PROJECT_ROOT / "output"
PRACTICE_DIR = PROJECT_ROOT / "practice"
EVENTS_FILE = "dlp_events.jsonl"


def configure_console() -> None:
    """Prevent consoles with limited encodings from crashing on unusual characters."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def display_path(path: Path) -> str:
    """Show the path relative to the current directory when possible."""
    try:
        return Path(path).resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return str(path)


def log_event(event: dict, directory: Path = OUTPUT_DIR) -> Path:
    """Append a JSON event (one per line) that a SIEM such as Wazuh could collect.

    Events contain metadata only (types, counts, files and rules), never the
    sensitive values or secrets that were detected.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": "cetys-dlp-lab",
        **event,
    }
    path = directory / EVENTS_FILE
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
    return path
