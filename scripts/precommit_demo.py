"""Optional exercise B3 - Gitleaks as a pre-commit hook.

Creates an ISOLATED temporary Git repository at practice/precommit_repo and
installs a pre-commit hook only in that repository. It never touches the global
Git configuration or the hooks of the main project.

Steps shown:
  1. A commit without secrets is accepted.
  2. A commit containing the fictional credential is rejected by Gitleaks.
  3. The hook is bypassed with --no-verify (bad practice) and the secret enters history.
  4. The secret is removed in a new commit.
  5. "gitleaks dir" (current files) vs "gitleaks git" (history) are compared.

Usage:
  python scripts/precommit_demo.py
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lab_utils import PRACTICE_DIR, configure_console, display_path  # noqa: E402
from reset_demo import safe_remove  # noqa: E402
from scan_secrets import GITLEAKS_CONFIG, GitleaksError, find_gitleaks, run_gitleaks  # noqa: E402
from setup_demo import create_fixed_config, create_vulnerable_config  # noqa: E402

DEMO_REPO = PRACTICE_DIR / "precommit_repo"

HOOK_TEMPLATE = """#!/bin/sh
# CETYS DLP lab demo hook. Installed ONLY in this isolated repository.
"{gitleaks}" git --pre-commit --staged --redact --verbose --no-banner --config "{config}"
"""


def git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, env=env, timeout=120)


def show_output(proc: subprocess.CompletedProcess) -> None:
    for line in (proc.stdout + proc.stderr).strip().splitlines():
        print(f"    | {line}")


def create_repository(repo: Path, gitleaks: str) -> None:
    if repo.exists():
        safe_remove(repo)
    repo.mkdir(parents=True)
    git(repo, "-c", "init.defaultBranch=main", "init", "-q")
    # Local settings only (written to this repository's .git/config).
    git(repo, "config", "user.name", "CETYS DLP Lab")
    git(repo, "config", "user.email", "lab@example.com")
    git(repo, "config", "commit.gpgsign", "false")

    hooks_dir = repo / ".git" / "hooks"
    hook = hooks_dir / "pre-commit"
    hook.write_text(
        HOOK_TEMPLATE.format(gitleaks=Path(gitleaks).as_posix(), config=GITLEAKS_CONFIG.as_posix()),
        encoding="utf-8",
        newline="\n",
    )
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    # A local core.hooksPath takes precedence over any global value the user may have.
    git(repo, "config", "core.hooksPath", hooks_dir.as_posix())


def run_demo(repo: Path = DEMO_REPO, gitleaks: str | None = None) -> dict:
    """Run the full demonstration and return the observed results."""
    gitleaks = gitleaks or find_gitleaks()
    if not gitleaks:
        raise GitleaksError("Gitleaks is not installed or not on the PATH.")

    results = {}
    print(f"Step 1: create an isolated Git repository at {display_path(repo)}")
    create_repository(repo, gitleaks)
    print("        Local pre-commit hook installed (global configuration untouched).")

    print("\nStep 2: commit without secrets")
    (repo / "README.md").write_text("# Payments Portal (fictional)\n", encoding="utf-8")
    git(repo, "add", "README.md")
    proc = git(repo, "commit", "-m", "Initial commit")
    results["clean_commit_accepted"] = proc.returncode == 0
    print(f"        -> {'ACCEPTED' if proc.returncode == 0 else 'REJECTED (unexpected)'}")

    print("\nStep 3: try to commit a file containing the fictional credential")
    create_vulnerable_config(repo)
    git(repo, "add", "config.py")
    proc = git(repo, "commit", "-m", "Add payments configuration")
    results["secret_commit_rejected"] = proc.returncode != 0
    show_output(proc)
    print(f"        -> {'REJECTED by Gitleaks' if proc.returncode != 0 else 'ACCEPTED (unexpected)'}")

    print("\nStep 4: bypass the hook with --no-verify (BAD PRACTICE)")
    proc = git(repo, "commit", "--no-verify", "-m", "Add payments configuration (bypassing hook)")
    results["bypass_commit_accepted"] = proc.returncode == 0
    print("        -> The commit was accepted: client-side hooks can be bypassed.")

    print("\nStep 5: remove the secret and commit the fix")
    create_fixed_config(repo)
    git(repo, "add", "config.py")
    proc = git(repo, "commit", "-m", "Read token from environment variable")
    results["fix_commit_accepted"] = proc.returncode == 0
    print(f"        -> {'ACCEPTED' if proc.returncode == 0 else 'REJECTED (unexpected)'}")

    print("\nStep 6: compare scans")
    current = run_gitleaks(repo, "dir", gitleaks)
    history = run_gitleaks(repo, "git", gitleaks)
    results["dir_findings"] = len(current.findings)
    results["git_findings"] = len(history.findings)
    print(f"        gitleaks dir (current files): {len(current.findings)} finding(s)")
    print(f"        gitleaks git (commit history): {len(history.findings)} finding(s)")
    for finding in history.findings:
        print(f"          commit {str(finding.get('Commit'))[:12]} | {finding.get('File')}:{finding.get('StartLine')} | {finding.get('RuleID')}")

    print("\nConclusion: deleting the secret from the current file does not remove it from")
    print("history. Once exposed, the credential must be revoked and rotated.")
    return results


def main() -> int:
    configure_console()
    try:
        results = run_demo()
    except GitleaksError as error:
        print(f"[ERROR] {error}")
        return 1
    expected = (
        results["clean_commit_accepted"]
        and results["secret_commit_rejected"]
        and results["fix_commit_accepted"]
        and results["dir_findings"] == 0
        and results["git_findings"] >= 1
    )
    print(f"\n[{'OK' if expected else 'WARNING'}] Demonstration {'completed as expected' if expected else 'produced unexpected results'}.")
    return 0 if expected else 1


if __name__ == "__main__":
    sys.exit(main())
