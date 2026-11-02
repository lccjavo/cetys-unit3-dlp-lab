# Instructor Guide - Lab 3.5: Data Loss Prevention (DLP)

This guide is for the instructor only. The student instructions are in
[`STUDENT_LAB.md`](../STUDENT_LAB.md).

It is a **guided, ungraded** lab: there are no deliverables, rubrics or reports.

## Suggested timing (40 minutes)

| Time | Activity |
| --- | --- |
| 5 min | Environment check (`python scripts/check_env.py`) |
| 15 min | Part A - DataFog (analyze, allow, block, anonymize, inspect) |
| 15 min | Part B - Gitleaks (detect, fix, rescan; optional pre-commit demo) |
| 5 min | Classroom discussion |

If time is short, run the optional pre-commit demo (B7) yourself on the projector.

## Classroom preparation

1. **Ask students to install in advance** (or reserve the first minutes): Python 3.10+,
   Git, and Gitleaks. The rest is installed with `pip`.
2. **Test the lab on a lab machine** the day before:

   ```bash
   git clone https://github.com/lccjavo/cetys-unit3-dlp-lab.git
   cd cetys-unit3-dlp-lab
   python3 -m venv .venv && source .venv/bin/activate   # Windows: py -m venv .venv; .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements-dev.txt
   python scripts/check_env.py
   python -m pytest -v
   ```

   All tests should pass. Gitleaks tests appear as `SKIPPED` if Gitleaks is not
   installed; that indicates an installation gap, not a lab defect.
3. **Restricted networks:** `pip` needs access to PyPI and Gitleaks must be downloaded
   from GitHub or a package manager. If the network is restricted, distribute the
   `datafog-core` wheel and the Gitleaks binary locally. The exercises themselves need
   **no network access**: DataFog's rule-based detection runs locally.
4. Have the projector ready to show the commands while students follow along.

## Demonstration commands and expected results

### Part A - DataFog

| Command | Expected result | Exit code |
| --- | --- | --- |
| `python src/demo_datafog.py analyze data/public_customers.csv` | `DataFog findings: none.` | 0 |
| `python src/demo_datafog.py analyze data/sensitive_customers.csv` | 19 findings: 10 `EMAIL`, 9 `PHONE` (3 of them in `notes`) | 0 |
| `python src/demo_datafog.py export data/public_customers.csv` | `[ALLOWED]`, creates `output/public_customers_export.csv` | 0 |
| `python src/demo_datafog.py export data/sensitive_customers.csv` | `[BLOCKED]`, no file is created | 2 |
| `python src/demo_datafog.py anonymize data/sensitive_customers.csv` | `[ALLOWED WITH PROTECTION]`, 0 remaining, 8 -> 8 records | 0 |

Content of `output/sensitive_customers_anonymized.csv` (first rows):

```text
customer_id,name,email,phone,city,plan,notes
C-2001,Ana Ramirez Soto,[EMAIL],[PHONE],Mexicali,Basic,Frequent customer
C-2002,Luis Hernandez Vega,[EMAIL],[PHONE],Tijuana,Enterprise,Alternate contact: [EMAIL]
```

**Points to highlight:**

- **Separation of responsibilities.** DataFog only detects (`scan`) and transforms
  (`scan_and_transform`); the decision lives in `src/export_policy.py`
  (`PROTECTED_ENTITIES = ("EMAIL", "PHONE")`). The same detector can serve different
  policies.
- **Data in unexpected places.** Three findings come from the free-text `notes` column.
- **Detection limits.** Names are not anonymized: the policy does not include them, and
  DataFog's plain-text rules do not detect names (it supports `PERSON` only in structured
  JSON scans or with optional local models). Good DLP depends on configuration and
  coverage, not just on the tool.
- **The tool must not leak.** The program shows row/column/type, never values, and the
  events in `output/dlp_events.jsonl` contain only counts.
- **Configuration detail.** The scan selects `EMAIL` and `PHONE` explicitly. DataFog also
  enables `DATE` and `ZIP_CODE` by default, which would flag harmless values such as dates
  or postal codes. Choosing what to look for reduces false positives.

### Part B - Gitleaks

| Command | Expected result | Exit code |
| --- | --- | --- |
| `python scripts/setup_demo.py` | Creates `practice/app/config.py` with a random token | 0 |
| `gitleaks dir practice/app --config .gitleaks.toml --redact --verbose` | 1 finding: `RuleID: cetys-lab-token`, `File: practice/app/config.py`, `Line: 8`, `Secret: REDACTED` | 1 |
| *(student edits line 8)* or `python scripts/setup_demo.py --fix` | Credential replaced with `os.environ.get(...)` | 0 |
| `gitleaks dir practice/app --config .gitleaks.toml --redact --verbose` | `no leaks found` | 0 |
| `python scripts/scan_secrets.py` | Plain-language summary; returns 0 whether or not there are findings | 0 |
| `python scripts/precommit_demo.py` *(optional)* | Clean commit accepted, secret commit rejected, `dir`: 0 vs `git`: 1 | 0 |

**Points to highlight:**

- **Exit codes.** Gitleaks returns `1` both for "leaks found" and for fatal errors (for
  example, a missing config file). `scripts/scan_secrets.py` uses `--exit-code 42` to tell
  them apart, and reports a demonstration with findings as a success.
- **Missing paths.** `gitleaks dir` on a path that does not exist reports
  `no leaks found` with exit code 0. A typo can produce a false "clean" result.
  `scan_secrets.py` checks that the path exists first.
- **`dir` vs `git`.** `gitleaks dir` scans current files (including ignored ones);
  `gitleaks git` scans commit history. The pre-commit demo shows that a secret deleted in
  a later commit is still found in history. The correct response is to **revoke and
  rotate** the credential, not just delete it.
- **Hooks are client-side.** `git commit --no-verify` bypasses them; organizations also
  scan on the server side (CI or push protection).
- **Custom rule.** `.gitleaks.toml` extends the default rules (`useDefault = true`) and
  adds `cetys-lab-token`. No tracked file contains a full token: tokens are generated at
  runtime with `secrets.choice`, so the rule causes no false positives in documentation.
  This is verified by `test_lab_rule_has_no_findings_in_project_files`.

## Common installation issues

| Symptom | Cause | Fix |
| --- | --- | --- |
| `ERROR: No matching distribution found for datafog-core==1.0.0` | Python older than 3.10 | Install Python 3.10+ and recreate `.venv` |
| `ModuleNotFoundError: No module named 'datafog_core'` | Virtual environment not active | Activate `.venv` and rerun `pip install -r requirements.txt` |
| Students installed `datafog` instead of `datafog-core` | Old package with a different API | `pip uninstall datafog` and install from `requirements.txt` |
| `gitleaks: command not found` / not recognized | Binary not on `PATH` | Reopen the terminal after `winget`; on Linux add `~/.local/bin` to `PATH` |
| `unknown command "dir"` | Gitleaks older than 8.19.0 | Update Gitleaks |
| PowerShell: `running scripts is disabled on this system` | Execution policy | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| `python` opens the Microsoft Store (Windows) | App execution alias | Use `py`, or disable the alias in Settings |
| `python3: command not found` (Windows) | Windows uses `py`/`python` | Use `py -m venv .venv` |
| macOS: `"gitleaks" cannot be opened` (downloaded binary) | Gatekeeper | Prefer `brew install gitleaks` |
| Corporate proxy blocks `pip` | Network policy | `pip install --proxy http://host:port -r requirements.txt` or offline wheels |

## Troubleshooting

- **Run the environment check first:** `python scripts/check_env.py` shows which piece is
  missing.
- **Gitleaks shows no finding in B2:** check that `python scripts/setup_demo.py` was run
  from the project root, and that the command includes `--config .gitleaks.toml` (without
  it, Gitleaks looks for a `.gitleaks.toml` inside the scanned directory).
- **Gitleaks still finds the secret after the fix:** the line still contains a
  `cetyslab_sk_...` value (for example, it was commented out instead of removed). Use
  `python scripts/setup_demo.py --fix`.
- **Weird characters (`[1;3;m`) in Gitleaks output:** old Windows console without ANSI
  support. Add `--no-color` or use Windows Terminal.
- **The pre-commit demo reports `WARNING`:** check `git --version` and that Gitleaks is on
  `PATH`. On Windows, Git for Windows runs hooks with its bundled `sh`. The demo only
  writes local settings to `practice/precommit_repo/.git/config`.
- **Students want to see the actual token:** it is in `practice/app/config.py`. It is
  fictional and random, regenerated on every run.

## Reset procedure

```bash
python scripts/reset_demo.py
```

Deletes `practice/` (including the temporary pre-commit repository) and every generated
file in `output/` except `.gitkeep`. It refuses to delete anything outside those two
directories. After resetting, all exercises can be run again from the beginning.

Check that nothing generated is pending:

```bash
git status --short
```

## Answers to the discussion questions

1. **Detecting vs. blocking.** Detection identifies and classifies sensitive data
   (DataFog's job); blocking is a decision based on a policy (the application's job). You
   can detect without blocking (audit/monitor mode), and the same detection can lead to
   different actions depending on context, user or destination. Separating them lets you
   change the policy without changing the detector, and reduces business impact from
   false positives.
2. **Anonymization vs. blocking.** Many exports are legitimate (analytics, reporting,
   testing). Blocking stops the business and pushes users toward insecure workarounds
   (copying data by hand, personal email). Anonymization lets the operation continue
   while removing the data that creates risk, applying data minimization (privacy laws
   such as Mexico's LFPDPPP or the GDPR). It must be verified: here the result is
   rescanned before export. Note that redaction is irreversible; pseudonymization or
   tokenization keeps the ability to re-identify under control.
3. **Credentials in source code.** They are copied to every clone, fork, backup and CI
   log; they persist in Git history even after deletion; they are hard to rotate; anyone
   with read access can use them; and public repositories are scanned by attackers within
   minutes. Use environment variables, secret managers (Vault, AWS Secrets Manager, Azure
   Key Vault) and short-lived credentials, plus scanning before commit and in CI.
4. **Why Gitleaks is not enterprise DLP.** Gitleaks only scans source code and Git
   history for secrets, based on patterns. Enterprise DLP covers many channels (email,
   web, endpoints, USB, cloud, printing), many data types (personal, financial,
   intellectual property), document classification, OCR, user context, centralized
   policies, real-time blocking, workflows and compliance reports. Gitleaks is a
   valuable, specialized control in the development pipeline and complements a broader
   DLP strategy.
5. **Centralization with Wazuh.** Both tools can produce JSON (`output/dlp_events.jsonl`
   and the Gitleaks `--report-format json` report). A Wazuh agent reads those files
   (`localfile` with `log_format json`), the manager decodes them with the built-in JSON
   decoder, and custom rules raise alerts (for example, a high-level alert for
   `export_blocked` or `secrets_detected`). This allows correlation across machines and
   users, dashboards and alert notifications. See
   [`WAZUH_INTEGRATION.md`](WAZUH_INTEGRATION.md).

## Repository validation (instructor)

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -v
```

The tests use the real tools and verify detection, blocking, anonymization, CSV
structure, Git ignore rules, Gitleaks detection and remediation, the isolated pre-commit
demo and reset safety. They do not grade students.
