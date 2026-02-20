"""
OWASP Security Scanner — Orchestration entry point.

Usage:
    python -m CBRS-503 [path]          # path = file or directory (default: ./project)
    python -m CBRS-503 ./project/vulnerable_app.py
    python -m CBRS-503 ./project
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

from chuncks_splitter import get_all_code_tasks
from models import (
    CodeChunk,
    FinalFinding,
    FinalReport,
    OWASPFindingReport,
    OWASPFunctionReport,
    OWASPVulnerabilityActionable,
    VerificationReport,
    VulnerabilityMitigation,
)
from agent import agent_finder, agent_mitigator, agent_verifier
from printer import (
    print_error,
    print_header,
    print_info,
    print_success,
    print_summary,
    print_vulnerability,
    print_warning,
)
from report_writer import write_reports


# ── Helpers ───────────────────────────────────────────────────────────────────

def _normalize(raw, model_cls):
    """Coerce an agent response into the expected Pydantic model."""
    if isinstance(raw, model_cls):
        return raw
    if isinstance(raw, dict) and "structured_response" in raw:
        return raw["structured_response"]
    if hasattr(raw, "structured_response"):
        return raw.structured_response
    if isinstance(raw, dict):
        try:
            return model_cls.model_validate(raw)
        except Exception:
            pass
    return None


# ── Stage 1 + 2: Finder → Mitigator per chunk ────────────────────────────────

def analyze_code_chunk(code_chunk: CodeChunk) -> OWASPFunctionReport:
    """
    Two-stage pipeline:
      1. agent_finder    — identify all vulnerabilities in the chunk.
      2. agent_mitigator — for each finding, produce a mitigation + fixed code.
    Returns an OWASPFunctionReport with fully actionable vulnerabilities.
    """
    file_path    = code_chunk.file
    context      = code_chunk.context
    code_segment = code_chunk.code_segment

    # ── Stage 1: Find vulnerabilities ────────────────────────────────────────
    finder_prompt = (
        f"File: {file_path}\n"
        f"Context:\n{context}\n\n"
        f"Code segment:\n```\n{code_segment}\n```"
    )
    raw_findings = agent_finder.invoke({"messages": [{"role": "user", "content": finder_prompt}]})
    finding_report: OWASPFindingReport | None = _normalize(raw_findings, OWASPFindingReport)

    if finding_report is None:
        print_warning(f"Finder returned an unparseable response for {file_path}.")
        return OWASPFunctionReport(vulnerabilities=[])

    findings = finding_report.vulnerabilities or []
    if not findings:
        return OWASPFunctionReport(vulnerabilities=[])

    # ── Stage 2: Enrich each finding with mitigation + fixed code ────────────
    actionable: list[OWASPVulnerabilityActionable] = []
    for finding in findings:
        mitigator_prompt = (
            f"Vulnerability finding:\n"
            f"  OWASP ID: {finding.owasp_id}\n"
            f"  Name: {finding.name}\n"
            f"  Description: {finding.description}\n"
            f"  Evidence: {finding.evidence}\n"
            f"  Vulnerable lines: {finding.line_start}–{finding.line_end}\n"
            f"  Exploitation steps: {finding.exploitation_steps}\n"
            f"  Impact: {finding.impact}\n\n"
            f"Original vulnerable code segment (1-indexed lines):\n```\n{code_segment}\n```"
        )
        raw_mitigation = agent_mitigator.invoke({"messages": [{"role": "user", "content": mitigator_prompt}]})
        mitigation: VulnerabilityMitigation | None = _normalize(raw_mitigation, VulnerabilityMitigation)

        if mitigation is None:
            print_warning(f"Mitigator returned an unparseable response for {finding.owasp_id} — skipping.")
            mit_text, fix_line_start, fix_line_end, fixed_code = "(unavailable)", 0, 0, "(unavailable)"
        else:
            mit_text       = mitigation.mitigation
            fix_line_start = mitigation.fix_line_start
            fix_line_end   = mitigation.fix_line_end
            fixed_code     = mitigation.fixed_code

        actionable.append(OWASPVulnerabilityActionable(
            owasp_id          = finding.owasp_id,
            name              = finding.name,
            risk_summary      = finding.risk_summary,
            description       = finding.description,
            evidence          = finding.evidence,
            line_start        = finding.line_start,
            line_end          = finding.line_end,
            exploitation_steps= finding.exploitation_steps,
            impact            = finding.impact,
            confidence        = finding.confidence,
            mitigation        = mit_text,
            fix_line_start    = fix_line_start,
            fix_line_end      = fix_line_end,
            fixed_code        = fixed_code,
        ))

    return OWASPFunctionReport(vulnerabilities=actionable)


# ── Stage 3: Verification pass ────────────────────────────────────────────────

def _verify_findings(
    all_findings: list[tuple[str, OWASPVulnerabilityActionable]]
) -> list[tuple[str, OWASPVulnerabilityActionable]]:
    """
    Submit all findings to agent_verifier.  Returns only confirmed findings
    with adjusted confidence values.
    """
    if not all_findings:
        return []

    # Serialise for the verifier
    payload = [
        {
            "index": i,
            "file": file_path,
            **vuln.model_dump(
                include={"owasp_id", "name", "risk_summary", "description",
                         "evidence", "line_start", "line_end",
                         "exploitation_steps", "impact", "confidence"}
            ),
        }
        for i, (file_path, vuln) in enumerate(all_findings)
    ]

    verifier_prompt = (
        "Review the following list of OWASP findings and decide which to keep.\n"
        "Drop: false positives, findings with impossibly vague evidence, and exact duplicates.\n\n"
        f"Findings (JSON):\n{json.dumps(payload, indent=2)}"
    )

    raw_verified = agent_verifier.invoke({"messages": [{"role": "user", "content": verifier_prompt}]})
    verification: VerificationReport | None = _normalize(raw_verified, VerificationReport)

    if verification is None:
        print_warning("Verifier returned an unparseable response — keeping all findings as-is.")
        return all_findings

    kept: list[tuple[str, OWASPVulnerabilityActionable]] = []
    decision_map = {d.index: d for d in verification.decisions}

    for i, (file_path, vuln) in enumerate(all_findings):
        decision = decision_map.get(i)
        if decision is None:
            # No decision → assume keep with original confidence
            kept.append((file_path, vuln))
        elif decision.keep:
            # Apply adjusted confidence
            adjusted = vuln.model_copy(update={"confidence": decision.adjusted_confidence})
            kept.append((file_path, adjusted))
        else:
            print_info(f"Verifier dropped [{i}] {vuln.owasp_id} in {file_path}: {decision.reason}")

    return kept


# ── Aggregation / deduplication ───────────────────────────────────────────────

def _dedup(
    verified: list[tuple[str, OWASPVulnerabilityActionable]]
) -> list[FinalFinding]:
    """
    Deduplicate by (file, owasp_id, line_start) — keep the entry with the
    highest confidence score.  Returns a flat list of FinalFinding objects.
    """
    best: dict[tuple[str, str, int], tuple[str, OWASPVulnerabilityActionable]] = {}

    for file_path, vuln in verified:
        key = (file_path, vuln.owasp_id, vuln.line_start)
        if key not in best or vuln.confidence > best[key][1].confidence:
            best[key] = (file_path, vuln)

    return [
        FinalFinding(
            file              = file_path,
            owasp_id          = v.owasp_id,
            name              = v.name,
            risk_summary      = v.risk_summary,
            description       = v.description,
            evidence          = v.evidence,
            line_start        = v.line_start,
            line_end          = v.line_end,
            exploitation_steps= v.exploitation_steps,
            impact            = v.impact,
            confidence        = v.confidence,
            mitigation        = v.mitigation,
            fix_line_start    = v.fix_line_start,
            fix_line_end      = v.fix_line_end,
            fixed_code        = v.fixed_code,
        )
        for file_path, v in best.values()
    ]


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    project_path = sys.argv[1] if len(sys.argv) > 1 else "./project"

    tasks = get_all_code_tasks(project_path)
    if not tasks:
        print_error(f"No source files found under: {project_path}")
        sys.exit(1)

    print_info(f"Scanning: {project_path}")
    print_info(f"Found {len(tasks)} chunk(s) to analyze across "
               f"{len({t.file for t in tasks})} file(s).")

    # ── Stages 1 + 2: finder → mitigator ─────────────────────────────────────
    all_findings: list[tuple[str, OWASPVulnerabilityActionable]] = []
    summary: dict[str, int] = {}

    for i, task in enumerate(tasks):
        file_path = task.file
        print_header(i + 1, len(tasks), file_path)

        try:
            chunk_report = analyze_code_chunk(task)
        except Exception as exc:
            print_error(f"Analysis failed for {file_path}: {exc}")
            continue

        vulns = chunk_report.vulnerabilities
        if not vulns:
            print_success("No OWASP Top-10 vulnerabilities found in this chunk.")
        else:
            for v in vulns:
                print_vulnerability(v)
                all_findings.append((file_path, v))

        summary[file_path] = summary.get(file_path, 0) + len(vulns)

    # ── Stage 3: Verification pass ────────────────────────────────────────────
    if all_findings:
        print_info(f"Running verification pass on {len(all_findings)} finding(s)…")
        try:
            verified = _verify_findings(all_findings)
        except Exception as exc:
            print_warning(f"Verification pass failed ({exc}) — continuing without it.")
            verified = all_findings
    else:
        verified = []

    # ── Aggregation / deduplication ───────────────────────────────────────────
    final_findings = _dedup(verified)
    unique_files   = len({t.file for t in tasks})

    final_report = FinalReport(
        scanned_path   = str(Path(project_path).resolve()),
        total_files    = unique_files,
        total_chunks   = len(tasks),
        total_findings = len(final_findings),
        findings       = final_findings,
    )

    # ── Write reports ─────────────────────────────────────────────────────────
    try:
        json_path, md_path = write_reports(final_report, output_dir=".")
        print_success(f"JSON report written → {json_path}")
        print_success(f"Markdown report written → {md_path}")
    except Exception as exc:
        print_error(f"Failed to write reports: {exc}")

    # ── Terminal summary ──────────────────────────────────────────────────────
    print_summary(summary)

    total = len(final_findings)
    if total > 0:
        print_error(f"{total} verified vulnerability/vulnerabilities detected — blocking deployment.")
        sys.exit(1)
    else:
        print_success("No verified vulnerabilities — safe to deploy.")
        sys.exit(0)
