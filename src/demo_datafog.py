"""Exercise A - Data Loss Prevention with DataFog Core.

Simulates an application that exports customer records from CSV files.

Responsibilities:
  * DataFog Core detects personal data (scan).
  * DataFog Core transforms the detected data (scan_and_transform).
  * export_policy.py decides whether the export is allowed or blocked.
  * This script only orchestrates those steps and shows the results.

Usage:
  python src/demo_datafog.py analyze   data/public_customers.csv
  python src/demo_datafog.py export    data/public_customers.csv
  python src/demo_datafog.py export    data/sensitive_customers.csv
  python src/demo_datafog.py anonymize data/sensitive_customers.csv

Exit codes: 0 = operation allowed, 1 = error, 2 = export blocked.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

try:
    from datafog_core import scan, scan_and_transform
except ImportError:  # pragma: no cover - guidance for students
    sys.exit(
        "DataFog Core was not found. Activate the virtual environment and run:\n"
        "  python -m pip install -r requirements.txt"
    )

from export_policy import ENTITY_LABELS, PROTECTED_ENTITIES, evaluate_export
from lab_utils import OUTPUT_DIR, configure_console, display_path, log_event

# The DataFog configuration is derived from the policy: only protected types are scanned.
SCAN_CONFIG = {"entities": list(PROTECTED_ENTITIES)}
ANONYMIZE_CONFIG = {
    "scan": SCAN_CONFIG,
    # "redact" replaces the value with its label: ana@example.com -> [EMAIL]
    "transform": {"default": {"strategy": "redact"}},
}

EXIT_ALLOWED = 0
EXIT_ERROR = 1
EXIT_BLOCKED = 2

MAX_ROWS_ON_SCREEN = 8


@dataclass(frozen=True)
class Finding:
    row: int  # 1 = first record after the header
    column: str
    entity_type: str
    value: str = field(repr=False)  # kept for the tests; never printed


def read_csv(path: Path) -> tuple[list[str], list[list[str]]]:
    with Path(path).open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        header = next(reader, [])
        rows = list(reader)
    return header, rows


def write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def detect(header: list[str], rows: list[list[str]]) -> list[Finding]:
    """Scan every cell with DataFog.

    The DataFog documentation recommends splitting CSV data into cells before
    scanning so that delimiters and adjacent fields do not affect matching.
    """
    findings = []
    for row_number, row in enumerate(rows, start=1):
        for column, cell in zip(header, row):
            if not cell:
                continue
            for match in scan(cell, SCAN_CONFIG):
                findings.append(Finding(row_number, column, match.entity_type, match.matched_text))
    return findings


def anonymize_rows(rows: list[list[str]]) -> list[list[str]]:
    """Use DataFog to replace detected data while keeping every row and column."""
    return [
        [scan_and_transform(cell, ANONYMIZE_CONFIG).text if cell else cell for cell in row]
        for row in rows
    ]


def print_findings(findings: list[Finding]) -> None:
    if not findings:
        print("DataFog findings: none.")
        return

    print(f"DataFog findings: {len(findings)}")
    for entity_type, count in sorted(Counter(f.entity_type for f in findings).items()):
        print(f"  - {entity_type:<6} ({ENTITY_LABELS.get(entity_type, entity_type)}): {count}")

    print("Columns where they appear:")
    for column, count in Counter(f.column for f in findings).most_common():
        print(f"  - {column}: {count}")

    print("Details (sensitive values are not shown on screen):")
    for f in findings[:MAX_ROWS_ON_SCREEN]:
        print(f"  row {f.row:>2} | column {f.column:<6} | {f.entity_type}")
    if len(findings) > MAX_ROWS_ON_SCREEN:
        print(f"  ... and {len(findings) - MAX_ROWS_ON_SCREEN} more findings")


def print_banner(title: str, path: Path, header: list[str], rows: list[list[str]]) -> None:
    print("=" * 64)
    print(f"{title}: {display_path(path)}")
    print("=" * 64)
    print(f"Records: {len(rows)} | Columns: {', '.join(header)}")
    print(f"Types protected by the policy: {', '.join(PROTECTED_ENTITIES)}")
    print()


def cmd_analyze(path: Path, output_dir: Path) -> int:
    header, rows = read_csv(path)
    print_banner("DataFog analysis", path, header, rows)
    print_findings(detect(header, rows))
    print()
    print("This command only detects; no policy has been applied yet.")
    return EXIT_ALLOWED


def cmd_export(path: Path, output_dir: Path) -> int:
    header, rows = read_csv(path)
    print_banner("Export request", path, header, rows)
    findings = detect(header, rows)
    print_findings(findings)
    decision = evaluate_export(f.entity_type for f in findings)
    print()

    if decision.allowed:
        target = output_dir / f"{path.stem}_export.csv"
        write_csv(target, header, rows)
        log_event(
            {"tool": "datafog", "action": "export_allowed", "file": path.name, "records": len(rows)},
            output_dir,
        )
        print(f"[ALLOWED] {decision.reason}")
        print(f"Exported file: {display_path(target)}")
        return EXIT_ALLOWED

    log_event(
        {
            "tool": "datafog",
            "action": "export_blocked",
            "file": path.name,
            "records": len(rows),
            "findings": decision.counts,
        },
        output_dir,
    )
    print(f"[BLOCKED] {decision.reason}")
    print("The policy forbids exporting unprotected personal data. No file was created.")
    print(f"Alternative: python src/demo_datafog.py anonymize {display_path(path)}")
    return EXIT_BLOCKED


def cmd_anonymize(path: Path, output_dir: Path) -> int:
    header, rows = read_csv(path)
    print_banner("DataFog anonymization", path, header, rows)
    findings = detect(header, rows)
    print_findings(findings)

    target = output_dir / f"{path.stem}_anonymized.csv"
    write_csv(target, header, anonymize_rows(rows))

    # Verification: the protected file is scanned again and checked against the policy.
    new_header, new_rows = read_csv(target)
    remaining = detect(new_header, new_rows)
    decision = evaluate_export(f.entity_type for f in remaining)
    structure_ok = new_header == header and len(new_rows) == len(rows)

    print()
    print("Verification of the anonymized file:")
    print(f"  - Records: {len(rows)} -> {len(new_rows)} | columns preserved: {'yes' if structure_ok else 'NO'}")
    print(f"  - Protected data remaining according to DataFog: {len(remaining)}")
    print(f"  - Policy decision: {'allowed' if decision.allowed else 'blocked'}")
    print()

    if not (decision.allowed and structure_ok):
        print("[ERROR] The anonymized file failed verification.")
        return EXIT_ERROR

    log_event(
        {
            "tool": "datafog",
            "action": "export_anonymized",
            "file": path.name,
            "records": len(rows),
            "findings_transformed": dict(Counter(f.entity_type for f in findings)),
        },
        output_dir,
    )
    print(f"[ALLOWED WITH PROTECTION] An anonymized copy was exported: {display_path(target)}")
    return EXIT_ALLOWED


COMMANDS = {
    "analyze": cmd_analyze,
    "export": cmd_export,
    "anonymize": cmd_anonymize,
}


def main(argv: list[str] | None = None) -> int:
    configure_console()
    parser = argparse.ArgumentParser(description="DLP demonstration with DataFog Core.")
    parser.add_argument("command", choices=COMMANDS, help="analyze, export or anonymize")
    parser.add_argument("file", type=Path, help="input CSV file")
    parser.add_argument("--output", type=Path, default=OUTPUT_DIR, help="export directory (default: output/)")
    args = parser.parse_args(argv)

    if not args.file.is_file():
        print(f"[ERROR] File not found: {args.file}")
        return EXIT_ERROR
    return COMMANDS[args.command](args.file, args.output)


if __name__ == "__main__":
    sys.exit(main())
