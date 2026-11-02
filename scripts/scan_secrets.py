"""Run Gitleaks and explain the result.

Gitleaks exits with a non-zero code when it finds secrets. In this lab,
finding the fictional secret is the EXPECTED result of step B1, not an
installation failure. This script tells the cases apart:

  * Gitleaks found secrets          -> the findings are shown (successful demo).
  * Gitleaks found no secrets       -> the scan is reported as clean.
  * Gitleaks is missing or crashed  -> a real error is reported.

Usage:
  python scripts/scan_secrets.py                                 # gitleaks dir practice/app
  python scripts/scan_secrets.py --mode git practice/precommit_repo
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lab_utils import (  # noqa: E402
    OUTPUT_DIR,
    PRACTICE_DIR,
    PROJECT_ROOT,
    configure_console,
    display_path,
    log_event,
)

GITLEAKS_CONFIG = PROJECT_ROOT / ".gitleaks.toml"
LAB_RULE = "cetys-lab-token"
MIN_VERSION = (8, 19, 0)  # first release with the "gitleaks dir" and "gitleaks git" commands

# Gitleaks uses exit code 1 both for "leaks found" and for fatal errors.
# --exit-code assigns findings a dedicated code so they can be told apart.
FINDINGS_EXIT_CODE = 42


class GitleaksError(RuntimeError):
    """Gitleaks is unavailable or could not complete the scan."""


@dataclass
class ScanResult:
    findings: list[dict]
    exit_code: int

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)


def find_gitleaks() -> str | None:
    """Look for Gitleaks in the GITLEAKS_BIN variable or on the PATH."""
    return os.environ.get("GITLEAKS_BIN") or shutil.which("gitleaks")


def gitleaks_version(binary: str) -> tuple[int, ...]:
    proc = subprocess.run([binary, "version"], capture_output=True, text=True, timeout=30)
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", proc.stdout + proc.stderr)
    if proc.returncode != 0 or not match:
        raise GitleaksError("Could not determine the Gitleaks version.")
    return tuple(int(part) for part in match.groups())


def run_gitleaks(
    path: Path,
    mode: str = "dir",
    binary: str | None = None,
    rules: list[str] | None = None,
) -> ScanResult:
    """Run "gitleaks dir" or "gitleaks git" with redacted output and a JSON report."""
    binary = binary or find_gitleaks()
    if not binary:
        raise GitleaksError("Gitleaks is not installed or not on the PATH.")
    # Gitleaks reports "no leaks found" for a path that does not exist; treat it as an error.
    if not Path(path).exists():
        raise GitleaksError(f"The path to scan does not exist: {path}")

    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        command = [
            binary, mode, str(path),
            "--config", str(GITLEAKS_CONFIG),
            "--redact",
            "--no-banner",
            "--log-level", "error",
            "--exit-code", str(FINDINGS_EXIT_CODE),
            "--report-format", "json",
            "--report-path", str(report),
        ]
        for rule in rules or []:
            command += ["--enable-rule", rule]

        proc = subprocess.run(command, capture_output=True, text=True, timeout=120)
        if proc.returncode not in (0, FINDINGS_EXIT_CODE):
            detail = (proc.stderr or proc.stdout).strip()
            raise GitleaksError(f"Gitleaks exited with code {proc.returncode}: {detail}")

        content = report.read_text(encoding="utf-8") if report.exists() else ""
        findings = json.loads(content) if content.strip() else []

    return ScanResult(findings or [], proc.returncode)


def print_result(result: ScanResult, mode: str) -> None:
    if not result.has_findings:
        print("[CLEAN] Gitleaks found no secrets (exit code 0).")
        return

    print(f"[FINDING] Gitleaks found {len(result.findings)} potential secret(s):")
    for finding in result.findings:
        file = Path(str(finding.get("File")))
        print(f"  - File:   {display_path(file) if file.is_absolute() else file.as_posix()}")
        print(f"    Line:   {finding.get('StartLine')}")
        print(f"    Rule:   {finding.get('RuleID')} ({finding.get('Description')})")
        print(f"    Secret: {finding.get('Secret')}")
        if mode == "git":
            print(f"    Commit: {str(finding.get('Commit', ''))[:12]}")
    print()
    print("Gitleaks exited with a non-zero code. In a CI pipeline this would stop the build.")
    print("In step B1 of the lab this is the EXPECTED result: the demonstration worked,")
    print("it is not an installation error.")


def main(argv: list[str] | None = None) -> int:
    configure_console()
    parser = argparse.ArgumentParser(description="Scan for secrets with Gitleaks and explain the result.")
    parser.add_argument("path", nargs="?", type=Path, default=PRACTICE_DIR / "app", help="path to scan (default: practice/app)")
    parser.add_argument("--mode", choices=("dir", "git"), default="dir", help="dir = current files; git = commit history")
    args = parser.parse_args(argv)

    binary = find_gitleaks()
    if not binary:
        print("[ERROR] Gitleaks is not installed or not on the PATH. See the installation section.")
        return 1
    try:
        version = gitleaks_version(binary)
        print(f"Gitleaks {'.'.join(map(str, version))} | mode: gitleaks {args.mode} | path: {display_path(args.path)}")
        if version < MIN_VERSION:
            print("[ERROR] Gitleaks 8.19.0 or newer is required for the 'dir' and 'git' commands.")
            return 1
        result = run_gitleaks(args.path, args.mode, binary)
    except GitleaksError as error:
        print(f"[ERROR] {error}")
        if not args.path.exists():
            print("If you have not generated the practice files yet, run: python scripts/setup_demo.py")
        return 1

    print()
    print_result(result, args.mode)
    log_event(
        {
            "tool": "gitleaks",
            "action": "secrets_detected" if result.has_findings else "scan_clean",
            "mode": args.mode,
            "findings": dict(Counter(f.get("RuleID") for f in result.findings)),
            "files": sorted({Path(str(f.get("File"))).name for f in result.findings}),
        },
        OUTPUT_DIR,
    )
    # The scan completed: with or without findings, the demonstration succeeded.
    return 0


if __name__ == "__main__":
    sys.exit(main())
