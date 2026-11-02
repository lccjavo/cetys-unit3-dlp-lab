# Lab 3.5 - Data Loss Prevention (DLP)

> **Guided classroom lab.** It is not graded and there is nothing to submit:
> you will run prepared examples, observe the results and discuss them as a group.
> Estimated time: **30-40 minutes**.

> **Warning:** every customer record, email address, phone number and credential
> in this lab is **fictional**. Never use real data in these exercises.

## Objective

Understand how two free, open-source tools help **identify sensitive information**
and **reduce the risk of exposing it**:

- **DataFog Core** detects personal data (email addresses and phone numbers) inside
  customer records and can anonymize it. An application uses those results to decide
  whether an export is allowed, blocked or protected.
- **Gitleaks** detects secrets (passwords, tokens, API keys) in configuration files and
  in Git history, before they reach a shared repository.

You will not write an application: you only run commands and observe the results.

---

## 1. Environment preparation (about 5 minutes)

### Requirements

- Python **3.10 or newer**
- Git
- Internet access only during installation (the exercises run entirely offline)

Check your versions:

```bash
python --version   # on Windows you can also use: py --version
git --version
```

> On macOS/Linux, if `python` does not exist or shows a version older than 3.10, use `python3`.

### 1.1 Clone the repository and enter the project

```bash
git clone https://github.com/lccjavo/cetys-unit3-dlp-lab.git
cd cetys-unit3-dlp-lab
```

### 1.2 Create and activate a virtual environment

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell)**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

> If PowerShell blocks the script, run
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and try again.

**Windows (Command Prompt / cmd)**

```bat
py -m venv .venv
.venv\Scripts\activate.bat
```

Your prompt should now start with `(.venv)`. From here on, use `python` on every
operating system.

> **`command not found: python`?** On macOS and many Linux systems, `python` only exists
> while the virtual environment is active. Run the activation command again (you need to
> do it in every new terminal window) and check that the prompt shows `(.venv)`.

### 1.3 Install the Python dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

This installs `datafog-core` (version 1.0.0).

### 1.4 Install Gitleaks

You need Gitleaks **8.19.0 or newer** (the lab was tested with 8.30.1).

**macOS (Homebrew)**

```bash
brew install gitleaks
```

**Windows (winget)**

```powershell
winget install --id Gitleaks.Gitleaks -e
```

Close and reopen the terminal afterwards (then reactivate `.venv`) so the `PATH` is
updated. Alternatives: `scoop install gitleaks` or `choco install gitleaks`.

**Linux (x64, official binary)**

```bash
cd /tmp
curl -sSLO https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz
tar -xzf gitleaks_8.30.1_linux_x64.tar.gz gitleaks
mkdir -p ~/.local/bin && install -m 755 gitleaks ~/.local/bin/gitleaks
cd -
```

Make sure `~/.local/bin` is on your `PATH`. For ARM, use the `linux_arm64` file.

### 1.5 Verify both tools

```bash
gitleaks version
python scripts/check_env.py
```

Every line should show `[OK]` and the script should end with
`Environment ready for the lab.`

---

## 2. Part A - DataFog (about 15 minutes)

The `src/demo_datafog.py` application simulates exporting customer records.
Pay attention to who does what:

| Component | Responsibility |
| --- | --- |
| DataFog Core (`scan`) | **Detects** email addresses and phone numbers |
| DataFog Core (`scan_and_transform`) | **Transforms** (anonymizes) what it detected |
| `src/export_policy.py` | The application **decides** whether to allow or block the export |

There are two fictional data sets:

- `data/public_customers.csv`: segment, city, plan... no personal data.
- `data/sensitive_customers.csv`: names, email addresses, phone numbers and notes.

### Step A1 - Analyze public information

```bash
python src/demo_datafog.py analyze data/public_customers.csv
```

**Observe:** `DataFog findings: none.` The file contains no protected data.

### Step A2 - Analyze sensitive information

```bash
python src/demo_datafog.py analyze data/sensitive_customers.csv
```

**Observe:**

- DataFog finds **10 email addresses** and **9 phone numbers**.
- Most are in the `email` and `phone` columns, but **3 appear in the `notes` column**,
  inside free text. Sensitive data often shows up where you do not expect it.
- The program shows the row, column and type, **not the values**: a DLP tool should
  not leak the data it is protecting.

### Step A3 - Try to export (allowed vs. blocked)

First the public file:

```bash
python src/demo_datafog.py export data/public_customers.csv
```

**Observe:** `[ALLOWED]` and the file `output/public_customers_export.csv` is created.

Now the sensitive file:

```bash
python src/demo_datafog.py export data/sensitive_customers.csv
```

**Observe:** `[BLOCKED]`. The policy prevents the export and **no file is created**.
The program ends with exit code `2`. You can check it with:

| Shell | Command |
| --- | --- |
| macOS / Linux | `echo $?` |
| PowerShell | `$LASTEXITCODE` |
| cmd | `echo %ERRORLEVEL%` |

An automated process (for example, a scheduled job) could use that code to stop.

### Step A4 - Generate an anonymized export

```bash
python src/demo_datafog.py anonymize data/sensitive_customers.csv
```

**Observe:**

- DataFog replaces each email address with `[EMAIL]` and each phone number with `[PHONE]`.
- The program **scans the result again**: `Protected data remaining according to DataFog: 0`.
- The number of records and columns is preserved.
- Result: `[ALLOWED WITH PROTECTION]`.

### Step A5 - Inspect the resulting CSV

**macOS / Linux**

```bash
cat output/sensitive_customers_anonymized.csv
```

**Windows (PowerShell)**

```powershell
Get-Content output\sensitive_customers_anonymized.csv
```

**Observe:**

- The `email` and `phone` columns now contain `[EMAIL]` and `[PHONE]`.
- In `notes`, only the embedded email or phone was replaced; the rest of the text remains.
- **Names were not anonymized.** The policy only protects `EMAIL` and `PHONE`.
  A detection tool only protects what it has been configured to look for.

> Optional: open `output/dlp_events.jsonl`. Each operation left a JSON event with
> counts and types only, never the values. These events could be sent to a SIEM
> (see the discussion question about Wazuh).

---

## 3. Part B - Gitleaks (about 15 minutes)

A developer saved a credential directly in a configuration file. You will detect it
with Gitleaks and fix it.

The `.gitleaks.toml` file keeps the official Gitleaks rules and adds a custom rule,
`cetys-lab-token`, that recognizes a **fictional** credential format used only in this
lab: `cetyslab_sk_` followed by 32 letters and digits.

### Step B1 - Generate the vulnerable configuration

```bash
python scripts/setup_demo.py
```

This creates `practice/app/config.py` with a random fictional token. The `practice/`
directory is listed in `.gitignore`, so it can never be committed by accident.

### Step B2 - Scan the directory with Gitleaks

```bash
gitleaks dir practice/app --config .gitleaks.toml --redact --verbose
```

- `dir` scans the **current files** in a directory.
- `--config` uses the lab rules.
- `--redact` hides the secret in the output (`REDACTED`).
- `--verbose` shows details of every finding.

### Step B3 - Identify the finding

In the output, locate:

| Field | Expected value | Meaning |
| --- | --- | --- |
| `RuleID` | `cetys-lab-token` | Rule that matched |
| `File` | `practice/app/config.py` | File containing the secret |
| `Line` | `8` | Line where the secret is |
| `Secret` | `REDACTED` | The value is hidden on purpose |

The final message says `leaks found: 1` and the exit code is `1`.

> **This is not an installation error.** Gitleaks returns a non-zero code when it finds
> secrets, so that a pipeline or a hook can stop. Here it means the demonstration worked.

For a summary in plain language you can also run:

```bash
python scripts/scan_secrets.py
```

### Step B4 - Fix the configuration

Open `practice/app/config.py` in your editor. Line 8 looks like this (with a different
random token):

```python
PAYMENTS_API_TOKEN = "cetyslab_sk_<32 random characters>"
```

Replace it so the credential is read from an environment variable, and add `import os`
at the top of the file:

```python
import os

PAYMENTS_API_TOKEN = os.environ.get("PAYMENTS_API_TOKEN", "")
```

Save the file.

> If you run out of time, this command writes the fixed version for you:
> `python scripts/setup_demo.py --fix`

### Step B5 - Scan again

```bash
gitleaks dir practice/app --config .gitleaks.toml --redact --verbose
```

### Step B6 - Confirm that the finding disappears

**Observe:** `no leaks found` and exit code `0`. The application still works, but the
credential no longer lives in the code: it is supplied by the environment or by a
secrets manager.

### Step B7 (optional) - Block the commit with a pre-commit hook

```bash
python scripts/precommit_demo.py
```

The script creates an **isolated** Git repository in `practice/precommit_repo`,
installs a Gitleaks hook **only in that repository** and shows:

1. A commit without secrets is **accepted**.
2. A commit with the fictional credential is **rejected** by Gitleaks.
3. With `git commit --no-verify` the hook can be skipped (bad practice): the secret
   enters the history.
4. The secret is removed in a new commit.
5. `gitleaks dir` finds **0** findings, but `gitleaks git` finds **1** in the history.

**Working files vs. Git history:**

- `gitleaks dir` reviews files as they are **now**.
- `gitleaks git` reviews **every commit** in the history. A secret deleted in a later
  commit is still recoverable from previous commits. Once a credential is exposed, it
  must be **revoked and rotated**; deleting it from the file is not enough.

You can repeat the history scan yourself:

```bash
gitleaks git practice/precommit_repo --config .gitleaks.toml --redact --verbose
```

### Reset the lab (optional)

To repeat the exercises from the beginning:

```bash
python scripts/reset_demo.py
```

It only deletes `practice/` and the generated files in `output/`.

---

## 4. Classroom discussion (about 5 minutes)

These questions are for group discussion only. You do not need to write or submit answers.

1. What is the difference between **detecting** sensitive information and **blocking** its export?
2. Why can **anonymization** be preferable to blocking a legitimate operation?
3. What risks arise from storing **credentials in source code**?
4. Why does Gitleaks **not replace** an enterprise DLP platform?
5. How could DataFog and Gitleaks events be **centralized using Wazuh**?

---

## References

- DataFog Core: <https://github.com/DataFog/datafog-core>
- Gitleaks: <https://github.com/gitleaks/gitleaks>
