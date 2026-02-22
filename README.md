# vulnerability-scan

[![PyPI version](https://img.shields.io/pypi/v/vulnerability-scan)](https://pypi.org/project/vulnerability-scan/)
[![Python](https://img.shields.io/pypi/pyversions/vulnerability-scan)](https://pypi.org/project/vulnerability-scan/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An AI-powered multi-agent static analysis tool that scans source code for **OWASP Top-10 vulnerabilities**. It uses a 4-stage LLM pipeline (split → find → mitigate → verify) and produces a structured `report.json`, a human-readable `report.md`, and an optional Word document report.

---

## Table of Contents

- [Installation](#installation)
- [API Key Setup](#api-key-setup)
- [Usage](#usage)
- [CLI Reference](#cli-reference)
- [Output Files](#output-files)
- [Exit Codes](#exit-codes)
- [Supported Languages](#supported-languages)
- [Pipeline Overview](#pipeline-overview)
- [CI/CD Integration](#cicd-integration)
- [Development](#development)

---

## Installation

**Requires Python ≥ 3.11**

```bash
pip install vulnerability-scan
```

Or install from source:

```bash
git clone https://github.com/alinoureldin707/vulnerability-scan.git
cd vulnerability-scan
pip install .
```

---

## API Key Setup

The tool requires a [Groq](https://console.groq.com) API key (free tier available). Provide it in **one of three ways** — highest priority first:

**1. CLI flag (per-run):**

```bash
vulnerability-scan ./project --api-key gsk_...
```

**2. Environment variable (per-session):**

```bash
# Linux / macOS
export GROQ_API_KEY=gsk_...

# Windows PowerShell
$env:GROQ_API_KEY = "gsk_..."

# Windows — persist permanently
[System.Environment]::SetEnvironmentVariable("GROQ_API_KEY", "gsk_...", "User")
```

**3. `.env` file (per-project):**

Create a `.env` file in the directory where you run the command:

```env
GROQ_API_KEY=gsk_...
```

---

## Usage

```bash
# Scan a directory
vulnerability-scan ./my-project

# Scan a single file
vulnerability-scan ./my-project/app.py

# Pass API key inline
vulnerability-scan ./my-project --api-key gsk_...

# Also generate a Word (.docx) report
vulnerability-scan ./my-project --report

# Run as a Python module (alternative)
python -m vul_scan ./my-project
```

---

## CLI Reference

```
usage: vulnerability-scan [path] [--api-key KEY] [--report] [-h]

positional arguments:
  path              File or directory to scan (default: ./project)

options:
  --api-key KEY     Groq API key — overrides GROQ_API_KEY env var and .env file
  --report          Generate Professional_Vulnerability_Report.docx in addition
                    to report.json and report.md
  -h, --help        Show this help message and exit
```

---

## Output Files

All files are written to the **current working directory**:

| File                                     | Description                                                                                         |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `report.json`                            | Machine-readable findings with OWASP IDs, evidence, exploitation steps, mitigations, and fixed code |
| `report.md`                              | Human-readable Markdown report with tables and code blocks                                          |
| `Professional_Vulnerability_Report.docx` | Word document report (only generated with `--report`)                                               |

### `report.json` structure

```jsonc
{
  "generated_at": "2026-02-22T10:00:00Z",
  "scanned_path": "/path/to/project",
  "total_files": 3,
  "total_chunks": 8,
  "total_findings": 2,
  "findings": [
    {
      "file": "app.py",
      "owasp_id": "A03:2021",
      "name": "SQL Injection",
      "risk_summary": "User input is concatenated directly into a SQL query.",
      "description": "...",
      "evidence": "query = 'SELECT * FROM users WHERE id=' + user_id",
      "chunk_line_start": 14,
      "chunk_line_end": 20,
      "exploitation_steps": ["Send input: 1 OR 1=1", "..."],
      "impact": "Full database read/write access",
      "confidence": 0.97,
      "mitigation": "Use parameterised queries or an ORM.",
      "fixed_code": "cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
    },
  ],
}
```

---

## Exit Codes

| Code | Meaning                                                   |
| ---- | --------------------------------------------------------- |
| `0`  | No verified vulnerabilities — safe to deploy              |
| `1`  | One or more vulnerabilities detected — deployment blocked |

---

## Supported Languages

| Language   | Extensions                           |
| ---------- | ------------------------------------ |
| Python     | `.py`                                |
| JavaScript | `.js`, `.jsx`                        |
| TypeScript | `.ts`, `.tsx`                        |
| Java       | `.java`                              |
| C / C++    | `.c`, `.cpp`, `.h`, `.hpp`           |
| C#         | `.cs`                                |
| Go         | `.go`                                |
| Ruby       | `.rb`                                |
| PHP        | `.php`                               |
| Rust       | `.rs`                                |
| Swift      | `.swift`                             |
| Kotlin     | `.kt`, `.kts`                        |
| Scala      | `.scala`                             |
| SQL        | `.sql`                               |
| Shell      | `.sh`, `.bash`, `.ps1`               |
| Config     | `.yaml`, `.yml`, `.json`, `.xml`     |
| Web        | `.html`, `.vue`, `.svelte`, `.astro` |

---

## Pipeline Overview

```
Source files
    │
    ▼
[agent_splitter]  — splits each file into logical chunks (functions / classes / routes)
    │
    ▼
[agent_finder]  — identifies OWASP Top-10 vulnerabilities per chunk
    │
    ▼
[agent_mitigator]  — produces fix recommendation + corrected code per finding
    │
    ▼
[agent_verifier]  — drops false positives, adjusts confidence scores
    │
    ▼
[aggregator]  — deduplicates by (file, OWASP ID, evidence)
    │
    ▼
report.json + report.md  [+ optional .docx]
```

---

## CI/CD Integration

Use the exit code to block deployments automatically:

```yaml
# GitHub Actions example
- name: Security Scan
  run: vulnerability-scan ./src --api-key ${{ secrets.GROQ_API_KEY }}
  # Exit code 1 automatically fails the workflow if vulnerabilities are found
```

---

## Development

Clone and install in editable mode so changes take effect immediately:

```bash
git clone https://github.com/alinoureldin707/vulnerability-scan.git
cd vulnerability-scan
pip install -e .
```

Run directly during development:

```bash
# CLI
vulnerability-scan ./vul-scan/project --api-key gsk_...

# As module
python -m vul_scan ./vul-scan/project --api-key gsk_...

# As script
python vul-scan/__main__.py ./vul-scan/project --api-key gsk_...
```
