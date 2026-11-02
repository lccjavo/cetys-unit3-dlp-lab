# CETYS Cybersecurity - Unit 3: Data Loss Prevention Lab

> **Guided, ungraded classroom lab** for topic **3.5 Data Loss Prevention (DLP)**.
> Students install the tools, run prepared examples, observe the results and discuss
> them. There are no grades, homework or deliverables. Duration: about 30-40 minutes.

> **Warning:** all customer data, email addresses, phone numbers and credentials in this
> repository are **fictional**. The lab credential is generated at runtime in an ignored
> directory and is never committed. Never use real data in these exercises.

## Overview

Two small, reproducible exercises show how open-source tools reduce the risk of
exposing sensitive information:

- **Exercise A - DataFog Core:** an application that exports customer CSV files.
  DataFog detects personal data, the application's policy decides whether to allow or
  block the export, and DataFog anonymizes the data so a protected copy can be exported.
- **Exercise B - Gitleaks:** detect a fictional credential in a configuration file with a
  custom rule, fix it, and (optionally) stop it with a pre-commit hook while comparing
  working-file scans with Git history scans.

## Learning objectives

- Distinguish **detecting** sensitive data from **enforcing** a policy on it.
- Apply three DLP outcomes: allow, block and anonymize.
- Detect hardcoded secrets and fix them with a safe configuration approach.
- Understand the difference between scanning working files and Git history.
- Recognize how these signals could be centralized in a SIEM such as Wazuh.

## Tools

| Tool | Version tested | Purpose |
| --- | --- | --- |
| [DataFog Core](https://github.com/DataFog/datafog-core) (`datafog-core`) | 1.0.0 | Detect and anonymize personal data (runs locally) |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | 8.30.1 (8.19.0+ required) | Detect secrets with `gitleaks dir` and `gitleaks git` |

## System requirements

- Windows, macOS or Linux
- Python 3.10 or newer
- Git
- Gitleaks CLI 8.19.0 or newer
- No Docker, databases, cloud services, accounts or API keys. Internet is only needed to
  install dependencies.

## Quick start

```bash
git clone https://github.com/lccjavo/cetys-unit3-dlp-lab.git
cd cetys-unit3-dlp-lab
python3 -m venv .venv
source .venv/bin/activate            # Windows PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Install Gitleaks (`brew install gitleaks`, `winget install --id Gitleaks.Gitleaks -e`,
or the [release binary](https://github.com/gitleaks/gitleaks/releases) on Linux), then:

```bash
python scripts/check_env.py
```

Detailed, OS-specific steps are in the student guide.

## Exercise A - DataFog

```bash
python src/demo_datafog.py analyze   data/public_customers.csv
python src/demo_datafog.py analyze   data/sensitive_customers.csv
python src/demo_datafog.py export    data/public_customers.csv      # [ALLOWED]  exit 0
python src/demo_datafog.py export    data/sensitive_customers.csv   # [BLOCKED]  exit 2
python src/demo_datafog.py anonymize data/sensitive_customers.csv   # protected copy in output/
```

## Exercise B - Gitleaks

```bash
python scripts/setup_demo.py                                           # create practice/app/config.py
gitleaks dir practice/app --config .gitleaks.toml --redact --verbose   # 1 finding (exit 1, expected)
# fix line 8 by hand, or: python scripts/setup_demo.py --fix
gitleaks dir practice/app --config .gitleaks.toml --redact --verbose   # no leaks found (exit 0)
python scripts/precommit_demo.py                                       # optional pre-commit + history demo
```

`python scripts/scan_secrets.py` runs the same scan and explains the result and exit
code in plain language.

Reset everything with `python scripts/reset_demo.py`.

## Documentation

- [Student guide: `STUDENT_LAB.md`](STUDENT_LAB.md)
- [Instructor guide: `docs/INSTRUCTOR_GUIDE.md`](docs/INSTRUCTOR_GUIDE.md)
- [Optional Wazuh integration (conceptual): `docs/WAZUH_INTEGRATION.md`](docs/WAZUH_INTEGRATION.md)
- Official docs: [DataFog Core](https://github.com/DataFog/datafog-core) ·
  [DataFog Core on PyPI](https://pypi.org/project/datafog-core/) ·
  [Gitleaks](https://github.com/gitleaks/gitleaks) ·
  [Gitleaks releases](https://github.com/gitleaks/gitleaks/releases)

## Project structure

```text
├── README.md
├── STUDENT_LAB.md              # student guide
├── requirements.txt            # datafog-core
├── requirements-dev.txt        # + pytest (repository validation)
├── .gitleaks.toml              # default rules + custom "cetys-lab-token" rule
├── data/                       # fictional CSV data sets
├── src/
│   ├── demo_datafog.py         # Exercise A CLI (DataFog detection/anonymization)
│   ├── export_policy.py        # allow/block decision (no DataFog code)
│   └── lab_utils.py            # paths and JSON event logging
├── scripts/
│   ├── check_env.py            # environment verification
│   ├── setup_demo.py           # generate vulnerable/fixed configuration
│   ├── scan_secrets.py         # Gitleaks wrapper with exit-code handling
│   ├── precommit_demo.py       # optional isolated pre-commit demo
│   └── reset_demo.py           # clean practice/ and output/
├── tests/test_lab.py           # integration tests with the real tools
├── docs/
│   ├── INSTRUCTOR_GUIDE.md
│   └── WAZUH_INTEGRATION.md
└── output/                     # generated exports and events (ignored by Git)
```

## Repository validation

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -v
```

The tests run the real DataFog and Gitleaks tools; Gitleaks tests are skipped if
Gitleaks is not installed. They validate the repository and are not used for grading.
