"""
Writes the final scan results to report.json and report.md.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

from models import FinalReport, FinalFinding


# ── Helpers ───────────────────────────────────────────────────────────────────

def _confidence_badge(c: float) -> str:
    if c >= 0.90:
        return "🔴 HIGH"
    if c >= 0.70:
        return "🟠 MEDIUM"
    return "🟡 LOW"


def _fmt_range(start: int, end: int) -> str:
    if not start and not end:
        return "unknown"
    if start == end or not end:
        return f"line {start}"
    return f"lines {start}–{end}"


# ── JSON ──────────────────────────────────────────────────────────────────────

def _to_json(report: FinalReport, generated_at: str) -> dict:
    return {
        "generated_at": generated_at,
        "scanned_path": report.scanned_path,
        "total_files": report.total_files,
        "total_chunks": report.total_chunks,
        "total_findings": report.total_findings,
        "findings": [f.model_dump() for f in report.findings],
    }


# ── Markdown ──────────────────────────────────────────────────────────────────

def _render_markdown(report: FinalReport, generated_at: str) -> str:
    lines: list[str] = []

    # ── Header ──
    lines += [
        "# OWASP Security Scan Report",
        "",
        f"**Generated:** {generated_at}  ",
        f"**Scanned path:** `{report.scanned_path}`  ",
        f"**Files scanned:** {report.total_files}  ",
        f"**Chunks analysed:** {report.total_chunks}  ",
        f"**Total findings:** {report.total_findings}  ",
        "",
    ]

    if not report.findings:
        lines += ["## ✅ No vulnerabilities found", ""]
        return "\n".join(lines)

    # ── Summary table ──
    lines += [
        "## Summary",
        "",
        "| # | File | OWASP ID | Name | Lines | Confidence |",
        "|---|------|----------|------|-------|------------|",
    ]
    for i, f in enumerate(report.findings, 1):
        loc = _fmt_range(f.line_start, f.line_end)
        badge = _confidence_badge(f.confidence)
        lines.append(
            f"| {i} | `{f.file}` | {f.owasp_id} | {f.name} | {loc} | {badge} ({f.confidence:.2f}) |"
        )
    lines.append("")

    # ── Findings grouped by file ──
    lines += ["## Findings", ""]
    by_file: dict[str, list[FinalFinding]] = defaultdict(list)
    for f in report.findings:
        by_file[f.file].append(f)

    finding_num = 0
    for file_path, findings in by_file.items():
        lines += [f"### 📄 `{file_path}`", ""]
        for f in findings:
            finding_num += 1
            loc      = _fmt_range(f.line_start, f.line_end)
            fix_loc  = _fmt_range(f.fix_line_start, f.fix_line_end)
            badge    = _confidence_badge(f.confidence)

            lines += [
                f"#### [{finding_num}] {f.owasp_id} — {f.name}",
                "",
                f"**Location:** {loc}  ",
                f"**Confidence:** {badge} ({f.confidence:.2f})  ",
                "",
                f"> {f.risk_summary}",
                "",
                f"**Description:** {f.description}",
                "",
                f"**Evidence:**",
                "```",
                f.evidence,
                "```",
                "",
            ]

            if f.exploitation_steps:
                lines.append("**Exploitation Steps:**")
                for s in f.exploitation_steps:
                    lines.append(f"1. {s}")
                lines.append("")

            lines += [
                f"**Impact:** {f.impact}",
                "",
                f"**Fix Recommendation ({fix_loc}):** {f.mitigation}",
                "",
                "**Fixed Code:**",
                "```python",
                f.fixed_code,
                "```",
                "",
                "---",
                "",
            ]

    # ── Prompt log ──
    try:
        from prompt import PROMPT_LOG
        lines += ["## Prompt Log", "```", PROMPT_LOG.strip(), "```", ""]
    except ImportError:
        pass

    return "\n".join(lines)


# ── Public API ────────────────────────────────────────────────────────────────

def write_reports(report: FinalReport, output_dir: str = ".") -> tuple[str, str]:
    """
    Write report.json and report.md to output_dir.
    Returns (json_path, md_path).
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    json_path = out / "report.json"
    md_path   = out / "report.md"

    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(_to_json(report, generated_at), fh, indent=2, ensure_ascii=False)

    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(_render_markdown(report, generated_at))

    return str(json_path), str(md_path)
