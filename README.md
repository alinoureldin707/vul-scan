# OWASP Security Scanner

A multi-agent static analysis pipeline that scans Python, JavaScript, and TypeScript source files for OWASP Top-10 vulnerabilities. It produces a structured `report.json` and a human-readable `report.md`.

---

## Pipeline Overview

```
Source files
    │
    ▼
[tree-sitter]  ── splits each file into logical chunks (functions / classes)
    │
    ▼
[agent_finder]  ── identifies OWASP Top-10 vulnerabilities per chunk
    │
    ▼
[agent_mitigator]  ── produces fix recommendation + corrected code per finding
    │
    ▼
[agent_verifier]  ── drops false positives, adjusts confidence scores
    │
    ▼
[aggregator]  ── deduplicates by (file, OWASP ID, line)
    │
    ▼
report.json + report.md
```

---

## Prerequisites

| Requirement  | Version                                      |
| ------------ | -------------------------------------------- |
| Python       | ≥ 3.11                                       |
| Groq API key | [console.groq.com](https://console.groq.com) |

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## Configuration

Create a `.env` file in the project root:

```env
GROQ_API_KEY=gsk_...
```

The model and temperature are set in `config.py`:

```python
MODEL_NAME  = "openai/gpt-oss-20b"   # any Groq-hosted model
TEMPERATURE = 0.0
```

---

## Usage

```bash
# Scan a directory (all .py / .js / .jsx / .ts / .tsx files)
python -m . ./project

# Scan a single file
python -m . ./project/vulnerable_app.py

# Default (scans ./project if no argument given)
python -m .
```

Outputs are written to the current working directory:

| File          | Description                                                          |
| ------------- | -------------------------------------------------------------------- |
| `report.json` | Machine-readable findings with risk analysis                         |
| `report.md`   | Human-readable report with severity tables, evidence, and fixed code |

---

## Output Format

### `report.json` structure

```jsonc
{
  "generated_at": "2026-02-20T19:22:13Z",
  "scanned_path": "...",
  "total_files": 5,
  "total_chunks": 7,
  "total_findings": 2,
  "risk_analysis": {
    // aggregate across all findings
    "overall_risk": "HIGH",
    "severity_breakdown": { "high": 2, "medium": 0, "low": 0 },
    "owasp_category_breakdown": { "A03:2021": 1 },
    "most_affected_files": [{ "file": "...", "findings": 2 }],
  },
  "findings": [
    {
      "file": "...",
      "owasp_id": "A03:2021",
      "name": "SQL Injection",
      "risk_summary": "...",
      "description": "...",
      "evidence": "...",
      "line_start": 10,
      "line_end": 14,
      "exploitation_steps": ["..."],
      "impact": "...",
      "confidence": 0.97,
      "mitigation": "...",
      "fix_line_start": 10,
      "fix_line_end": 14,
      "fixed_code": "...",
      "risk_analysis": {
        // per-finding risk analysis
        "severity": "HIGH",
        "likelihood": "HIGH",
        "risk_score": 9.7,
        "remediation_priority": "P1 — Immediate",
        "attack_vector": "Injection",
      },
    },
  ],
}
```

### Exit codes

| Code | Meaning                              |
| ---- | ------------------------------------ |
| `0`  | No verified vulnerabilities found    |
| `1`  | One or more vulnerabilities detected |

---

## Project Structure

```
.
├── __main__.py          # Orchestration entry point
├── agent.py             # LLM agent definitions (finder, mitigator, verifier)
├── chuncks_splitter.py  # tree-sitter file → CodeChunk splitting
├── config.py            # Model name, temperature, API key loading
├── models.py            # Pydantic data models for all pipeline stages
├── printer.py           # Rich terminal output helpers
├── prompt.py            # System prompts for all agents
├── report_writer.py     # report.json + report.md generation
├── .env                 # GROQ_API_KEY (not committed)
└── project/             # Example target code
    ├── vulnerable_app.py
    ├── no_vulnerable.py
    ├── test.py
    ├── test.js
    └── test.ts
```

---

## Supported Languages

| Language   | Extensions    |
| ---------- | ------------- |
| Python     | `.py`         |
| JavaScript | `.js`, `.jsx` |
| TypeScript | `.ts`, `.tsx` |
