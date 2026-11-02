"""Integration tests for the repository (they verify the lab, they do not grade students).

They use the real tools: DataFog Core and, when installed, the Gitleaks CLI.
Gitleaks tests are skipped if the binary is not available.

Usage:
  python -m pip install -r requirements-dev.txt
  python -m pytest -v
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import demo_datafog  # noqa: E402
import reset_demo  # noqa: E402
import scan_secrets  # noqa: E402
import setup_demo  # noqa: E402
from export_policy import evaluate_export  # noqa: E402

PUBLIC_CSV = ROOT / "data" / "public_customers.csv"
SENSITIVE_CSV = ROOT / "data" / "sensitive_customers.csv"

GITLEAKS = scan_secrets.find_gitleaks()
requires_gitleaks = pytest.mark.skipif(not GITLEAKS, reason="Gitleaks is not installed or not on the PATH")
requires_git_repo = pytest.mark.skipif(
    not shutil.which("git")
    or subprocess.run(["git", "rev-parse", "--git-dir"], cwd=ROOT, capture_output=True).returncode != 0,
    reason="The project is not inside a Git repository",
)


def column_values(path: Path, column: str) -> set[str]:
    header, rows = demo_datafog.read_csv(path)
    index = header.index(column)
    return {row[index] for row in rows}


def run_demo(command: str, csv_path: Path, output_dir: Path) -> int:
    return demo_datafog.main([command, str(csv_path), "--output", str(output_dir)])


# --- Exercise A: DataFog -------------------------------------------------------


def test_datafog_detects_expected_personal_data():
    findings = demo_datafog.detect(*demo_datafog.read_csv(SENSITIVE_CSV))
    detected = {(f.entity_type, f.value) for f in findings}

    for email in column_values(SENSITIVE_CSV, "email"):
        assert ("EMAIL", email) in detected
    for phone in column_values(SENSITIVE_CSV, "phone"):
        assert ("PHONE", phone) in detected
    # Values embedded in free text in the notes column are detected too.
    assert ("EMAIL", "lhv.purchasing@example.net") in detected
    assert ("PHONE", "+52 662 555 0199") in detected
    assert sum(f.entity_type == "EMAIL" for f in findings) == 10
    assert sum(f.entity_type == "PHONE" for f in findings) == 9


def test_public_data_does_not_trigger_policy():
    findings = demo_datafog.detect(*demo_datafog.read_csv(PUBLIC_CSV))
    assert findings == []
    assert evaluate_export(f.entity_type for f in findings).allowed


def test_allowed_export_is_generated(tmp_path):
    assert run_demo("export", PUBLIC_CSV, tmp_path) == demo_datafog.EXIT_ALLOWED
    exported = tmp_path / "public_customers_export.csv"
    assert exported.read_text(encoding="utf-8") == PUBLIC_CSV.read_text(encoding="utf-8")


def test_sensitive_export_is_blocked(tmp_path, capsys):
    assert run_demo("export", SENSITIVE_CSV, tmp_path) == demo_datafog.EXIT_BLOCKED
    assert not (tmp_path / "sensitive_customers_export.csv").exists()

    screen = capsys.readouterr().out
    assert "[BLOCKED]" in screen
    for value in column_values(SENSITIVE_CSV, "email") | column_values(SENSITIVE_CSV, "phone"):
        assert value not in screen, "sensitive values must not be printed"

    event = json.loads((tmp_path / "dlp_events.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert event["action"] == "export_blocked"
    assert event["findings"] == {"EMAIL": 10, "PHONE": 9}


def test_anonymized_export_does_not_expose_original_values(tmp_path):
    assert run_demo("anonymize", SENSITIVE_CSV, tmp_path) == demo_datafog.EXIT_ALLOWED
    anonymized = tmp_path / "sensitive_customers_anonymized.csv"
    content = anonymized.read_text(encoding="utf-8")

    original = {f.value for f in demo_datafog.detect(*demo_datafog.read_csv(SENSITIVE_CSV))}
    assert original
    for value in original:
        assert value not in content
    assert "[EMAIL]" in content and "[PHONE]" in content
    assert demo_datafog.detect(*demo_datafog.read_csv(anonymized)) == []

    events = (tmp_path / "dlp_events.jsonl").read_text(encoding="utf-8")
    for value in original:
        assert value not in events, "events must not contain sensitive values"


def test_csv_structure_is_preserved(tmp_path):
    run_demo("anonymize", SENSITIVE_CSV, tmp_path)
    header, rows = demo_datafog.read_csv(SENSITIVE_CSV)
    new_header, new_rows = demo_datafog.read_csv(tmp_path / "sensitive_customers_anonymized.csv")

    assert new_header == header
    assert len(new_rows) == len(rows)
    assert all(len(row) == len(header) for row in new_rows)
    for column in ("customer_id", "name", "city", "plan"):
        i = header.index(column)
        assert [r[i] for r in new_rows] == [r[i] for r in rows]


# --- Exercise B: Gitleaks ------------------------------------------------------


@requires_git_repo
def test_generated_files_are_ignored_by_git():
    paths = [
        "practice/app/config.py",
        "practice/precommit_repo/config.py",
        "output/sensitive_customers_anonymized.csv",
        "output/dlp_events.jsonl",
    ]
    for path in paths:
        result = subprocess.run(["git", "check-ignore", "-q", path], cwd=ROOT)
        assert result.returncode == 0, f"{path} should be ignored by Git"
    kept = subprocess.run(["git", "check-ignore", "-q", "output/.gitkeep"], cwd=ROOT)
    assert kept.returncode == 1, "output/.gitkeep must remain tracked"


def test_synthetic_token_matches_lab_format():
    token = setup_demo.generate_token()
    assert token.startswith(setup_demo.TOKEN_PREFIX)
    assert len(token) == len(setup_demo.TOKEN_PREFIX) + setup_demo.TOKEN_LENGTH
    assert token != setup_demo.generate_token()


@requires_gitleaks
def test_gitleaks_detects_synthetic_secret(tmp_path):
    config = setup_demo.create_vulnerable_config(tmp_path)
    result = scan_secrets.run_gitleaks(tmp_path)

    assert result.exit_code == scan_secrets.FINDINGS_EXIT_CODE
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding["RuleID"] == scan_secrets.LAB_RULE
    assert Path(finding["File"]).name == config.name
    assert finding["StartLine"] == 8
    assert finding["Secret"] == "REDACTED"
    token = config.read_text(encoding="utf-8").split('"')[-2]
    assert token not in json.dumps(result.findings), "the report must be redacted"


@requires_gitleaks
def test_fixed_configuration_is_clean(tmp_path):
    setup_demo.create_vulnerable_config(tmp_path)
    setup_demo.create_fixed_config(tmp_path)
    result = scan_secrets.run_gitleaks(tmp_path)
    assert result.exit_code == 0
    assert result.findings == []


@requires_gitleaks
def test_lab_rule_has_no_findings_in_project_files():
    for name in ("README.md", "STUDENT_LAB.md", "docs", "src", "scripts", "tests", "data", ".gitleaks.toml"):
        path = ROOT / name
        if path.exists():
            result = scan_secrets.run_gitleaks(path, rules=[scan_secrets.LAB_RULE])
            assert result.findings == [], f"accidental finding in {name}"


@requires_gitleaks
def test_gitleaks_reports_missing_path_as_error(tmp_path):
    with pytest.raises(scan_secrets.GitleaksError):
        scan_secrets.run_gitleaks(tmp_path / "does-not-exist")


@requires_gitleaks
def test_precommit_demo_in_isolated_repository():
    import precommit_demo

    repo = reset_demo.PRACTICE_DIR / "test_precommit_repo"
    try:
        results = precommit_demo.run_demo(repo)
    finally:
        if repo.exists():
            reset_demo.safe_remove(repo)

    assert results["clean_commit_accepted"]
    assert results["secret_commit_rejected"]
    assert results["fix_commit_accepted"]
    assert results["dir_findings"] == 0
    assert results["git_findings"] == 1


# --- Reset -----------------------------------------------------------------------


def test_reset_refuses_paths_outside_workspace(tmp_path):
    for path in (tmp_path, ROOT, ROOT / "data", ROOT / "output"):
        with pytest.raises(ValueError):
            reset_demo.safe_remove(path)
