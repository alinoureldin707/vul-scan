"""
Writes the final scan results to report.json and report.md.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

from models import FinalReport, FinalFinding


# ── Language detection ───────────────────────────────────────────────────────

_LANG_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "jsx",
    ".tsx": "tsx",
    ".java": "java",
    ".c": "c",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".swift": "swift",
    ".kt": "kotlin",
    ".sql": "sql",
    ".sh": "bash",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".html": "html",
    ".css": "css",
}


def _detect_language(file_path: str) -> str:
    """Detect programming language from file extension for code fences."""
    ext = os.path.splitext(file_path)[1].lower()
    return _LANG_MAP.get(ext, "text")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _confidence_badge(c: float) -> str:
    if c >= 0.90:
        return "🔴 HIGH"
    if c >= 0.70:
        return "🟠 MEDIUM"
    return "🟡 LOW"



def _finding_risk_analysis(f: FinalFinding) -> dict:
    """Compute a risk analysis block for a single finding."""
    # Severity — driven by confidence
    if f.confidence >= 0.90:
        severity = "HIGH"
    elif f.confidence >= 0.70:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # Likelihood — proxy: more exploitation steps = easier to exploit = higher likelihood
    steps = len(f.exploitation_steps)
    if steps >= 3:
        likelihood = "HIGH"
    elif steps == 2:
        likelihood = "MEDIUM"
    else:
        likelihood = "LOW"

    # Risk score — 0.0-10.0 using CVSS-inspired formula: confidence * severity_weight * likelihood_weight
    sev_w  = {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.3}[severity]
    like_w = {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.3}[likelihood]
    risk_score = round(f.confidence * sev_w * like_w * 10, 1)

    # Remediation priority
    if severity == "HIGH" and likelihood == "HIGH":
        priority = "P1 — Immediate"
    elif severity == "HIGH" or (severity == "MEDIUM" and likelihood == "HIGH"):
        priority = "P2 — High Priority"
    elif severity == "MEDIUM":
        priority = "P3 — Medium Priority"
    else:
        priority = "P4 — Low Priority"

    # Attack vector — inferred from OWASP ID (2025 categories)
    vector_map = {
        "A01": "Broken Access Control",
        "A02": "Security Misconfiguration",
        "A03": "Supply Chain Attack",
        "A04": "Cryptographic Failure",
        "A05": "Injection",
        "A06": "Insecure Design",
        "A07": "Authentication Failure",
        "A08": "Integrity Failure",
        "A09": "Logging Failure",
        "A10": "Exception Handling",
    }
    prefix = f.owasp_id[:3]  # e.g. "A03"
    attack_vector = vector_map.get(prefix, "Unknown")

    return {
        "severity": severity,
        "likelihood": likelihood,
        "risk_score": risk_score,
        "remediation_priority": priority,
        "attack_vector": attack_vector,
    }

# ── Risk Analysis ────────────────────────────────────────────────────────────

def _build_risk_analysis(report: FinalReport) -> dict:
    """Compute an aggregate risk analysis from all findings."""
    findings = report.findings

    high   = [f for f in findings if f.confidence >= 0.90]
    medium = [f for f in findings if 0.70 <= f.confidence < 0.90]
    low    = [f for f in findings if f.confidence < 0.70]

    # Overall risk level
    if high:
        overall = "CRITICAL" if len(high) >= 3 else "HIGH"
    elif medium:
        overall = "MEDIUM"
    elif low:
        overall = "LOW"
    else:
        overall = "NONE"

    # OWASP category distribution
    owasp_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        owasp_counts[f.owasp_id] += 1

    # File distribution
    file_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        file_counts[f.file] += 1
    top_files = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)

    return {
        "overall_risk": overall,
        "severity_breakdown": {
            "high":   len(high),
            "medium": len(medium),
            "low":    len(low),
        },
        "owasp_category_breakdown": dict(
            sorted(owasp_counts.items(), key=lambda x: x[1], reverse=True)
        ),
        "most_affected_files": [{"file": f, "findings": c} for f, c in top_files],
    }


# ── JSON ──────────────────────────────────────────────────────────────────────

def _to_json(report: FinalReport, generated_at: str) -> dict:
    findings_out = []
    for f in report.findings:
        d = f.model_dump()
        d["risk_analysis"] = _finding_risk_analysis(f)
        findings_out.append(d)
    return {
        "generated_at": generated_at,
        "scanned_path": report.scanned_path,
        "total_files": report.total_files,
        "total_chunks": report.total_chunks,
        "total_findings": report.total_findings,
        "risk_analysis": _build_risk_analysis(report),
        "findings": findings_out,
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

    # ── Risk Analysis ──
    ra = _build_risk_analysis(report)
    overall = ra["overall_risk"]
    level_icon = {"CRITICAL": "🔴", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "NONE": "✅"}.get(overall, "")
    sb = ra["severity_breakdown"]

    lines += [
        "## Risk Analysis",
        "",
        f"**Overall Risk Level:** {level_icon} **{overall}**",
        "",
        "### Severity Breakdown",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 High   | {sb['high']} |",
        f"| 🟠 Medium | {sb['medium']} |",
        f"| 🟡 Low    | {sb['low']} |",
        "",
        "### OWASP Category Distribution",
        "",
        "| OWASP ID | Findings |",
        "|----------|----------|",
    ]
    for owasp_id, count in ra["owasp_category_breakdown"].items():
        lines.append(f"| {owasp_id} | {count} |")
    lines.append("")

    lines += [
        "### Most Affected Files",
        "",
        "| File | Findings |",
        "|------|----------|",
    ]
    for entry in ra["most_affected_files"]:
        lines.append(f"| `{entry['file']}` | {entry['findings']} |")
    lines.append("")

    # ── Summary table ──
    lines += [
        "## Summary",
        "",
        "| # | File | Chunk Lines | OWASP ID | Name | Confidence |",
        "|---|------|-------------|----------|------|------------|",
    ]
    for i, f in enumerate(report.findings, 1):
        badge = _confidence_badge(f.confidence)
        line_info = f"{f.chunk_line_start}-{f.chunk_line_end}" if f.chunk_line_end else str(f.chunk_line_start)
        lines.append(
            f"| {i} | `{f.file}` | {line_info} | {f.owasp_id} | {f.name} | {badge} ({f.confidence:.2f}) |"
        )
    lines.append("")

    # ── Findings grouped by file ──
    lines += ["## Findings", ""]
    by_file: dict[str, list[FinalFinding]] = defaultdict(list)
    for f in report.findings:
        by_file[f.file].append(f)

    finding_num = 0
    for file_path, findings in by_file.items():
        lang = _detect_language(file_path)
        lines += [f"### 📄 `{file_path}`", ""]
        for f in findings:
            finding_num += 1
            badge    = _confidence_badge(f.confidence)
            fra      = _finding_risk_analysis(f)
            sev_icon = {"HIGH": "\U0001f534", "MEDIUM": "\U0001f7e0", "LOW": "\U0001f7e1"}.get(fra["severity"], "")
            like_icon= {"HIGH": "\U0001f534", "MEDIUM": "\U0001f7e0", "LOW": "\U0001f7e1"}.get(fra["likelihood"], "")

            lines += [
                f"#### [{finding_num}] {f.owasp_id} — {f.name}  (Chunk Lines {f.chunk_line_start}-{f.chunk_line_end})",
                "",
                f"**Confidence:** {badge} ({f.confidence:.2f})  ",
                "",
                f"> {f.risk_summary}",
                "",
                "**Risk Analysis**",
                "",
                "| Attribute | Value |",
                "|-----------|-------|",
                f"| Severity | {sev_icon} {fra['severity']} |",
                f"| Likelihood | {like_icon} {fra['likelihood']} |",
                f"| Risk Score | **{fra['risk_score']} / 10** |",
                f"| Remediation Priority | {fra['remediation_priority']} |",
                f"| Attack Vector | {fra['attack_vector']} |",
                "",
                f"**Description:** {f.description}",
                "",
                f"**Evidence:**",
                f"```{lang}",
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
                f"**Fix Recommendation:** {f.mitigation}",
                "",
                "**Fixed Code:**",
                f"```{lang}",
                f.fixed_code,
                "```",
                "",
                "---",
                "",
            ]

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
