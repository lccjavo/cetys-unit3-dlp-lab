"""Check that the environment is ready for the lab.

Usage:
  python scripts/check_env.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from importlib import metadata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lab_utils import configure_console  # noqa: E402
from scan_secrets import MIN_VERSION, GitleaksError, find_gitleaks, gitleaks_version  # noqa: E402


def check_python() -> tuple[bool, str]:
    version = ".".join(map(str, sys.version_info[:3]))
    return sys.version_info >= (3, 10), f"Python {version} (3.10+ required)"


def check_datafog() -> tuple[bool, str]:
    try:
        from datafog_core import scan

        version = metadata.version("datafog-core")
        works = [f.entity_type for f in scan("Email ana@example.com")] == ["EMAIL"]
        return works, f"datafog-core {version} ({'local scan OK' if works else 'unexpected scan result'})"
    except Exception as error:  # noqa: BLE001 - report any installation problem
        return False, f"datafog-core not available: {error}"


def check_git() -> tuple[bool, str]:
    if not shutil.which("git"):
        return False, "Git not found on the PATH"
    proc = subprocess.run(["git", "--version"], capture_output=True, text=True)
    return proc.returncode == 0, proc.stdout.strip()


def check_gitleaks() -> tuple[bool, str]:
    binary = find_gitleaks()
    if not binary:
        return False, "Gitleaks not found on the PATH"
    try:
        version = gitleaks_version(binary)
    except GitleaksError as error:
        return False, str(error)
    text = ".".join(map(str, version))
    return version >= MIN_VERSION, f"Gitleaks {text} (8.19.0+ required)"


def main() -> int:
    configure_console()
    checks = [check_python(), check_datafog(), check_git(), check_gitleaks()]
    for ok, message in checks:
        print(f"[{'OK' if ok else 'MISSING'}] {message}")
    ready = all(ok for ok, _ in checks)
    print()
    print("Environment ready for the lab." if ready else "Fix the items marked MISSING before continuing.")
    return 0 if ready else 1


if __name__ == "__main__":
    sys.exit(main())
