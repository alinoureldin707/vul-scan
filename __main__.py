"""
OWASP Security Scanner — Orchestration entry point.

Usage:
    python -m CBRS-503 [path]          # path = file or directory (default: ./project)
    python -m CBRS-503 ./project/vulnerable_app.py
    python -m CBRS-503 ./project
"""
import json
import sys
from pathlib import Path
from report_generator import create_advanced_vuln_report

from chunks_splitter import get_all_code_tasks
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
from utils import invoke_with_retry


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


def _invoke_agent(agent, prompt: str, model_cls, context: str):
    """Invoke an agent with retry logic and return normalized response."""
    def invoke():
        return agent.invoke({"messages": [{"role": "user", "content": prompt}]})
    
    def normalize(raw):
        return _normalize(raw, model_cls)
    
    return invoke_with_retry(invoke, normalize, context)


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
    chunk_line_start = code_chunk.line_start
    chunk_line_end   = code_chunk.line_end

    # ── Stage 1: Find vulnerabilities ────────────────────────────────────────
    finder_prompt = (
        f"=== ANALYSIS TARGET ===\n"
        f"File: {file_path}\n"
        f"Chunk: lines {chunk_line_start}–{chunk_line_end}\n\n"
        f"=== CONTEXT (imports, constants, config) ===\n"
        f"{context}\n\n"
        f"=== CODE TO ANALYZE ===\n"
        f"{code_segment}"
    )
    
    finding_report = _invoke_agent(
        agent_finder, finder_prompt, OWASPFindingReport, f"finder:{file_path}"
    )

    if finding_report is None:
        print_warning(f"Finder returned no parseable response for {file_path}.")
        return OWASPFunctionReport(vulnerabilities=[])

    findings = finding_report.vulnerabilities or []
    if not findings:
        return OWASPFunctionReport(vulnerabilities=[])

    # ── Stage 2: Enrich each finding with mitigation + fixed code ────────────
    actionable: list[OWASPVulnerabilityActionable] = []
    for finding in findings:
        # Truncate code to avoid overwhelming the mitigator
        code_for_mitigation = code_segment[:2000] if len(code_segment) > 2000 else code_segment
        mitigator_prompt = (
            f"VULNERABILITY: {finding.owasp_id} - {finding.name}\n"
            f"EVIDENCE: {finding.evidence}\n"
            f"DESCRIPTION: {finding.description}\n\n"
            f"CODE:\n{code_for_mitigation}"
        )
        
        mitigation = _invoke_agent(
            agent_mitigator, mitigator_prompt, VulnerabilityMitigation, f"mitigator:{finding.owasp_id}"
        )

        if mitigation is None:
            print_warning(f"Mitigator returned no parseable response for {finding.owasp_id} — using placeholder.")
            mit_text, fixed_code = "(unavailable)", "(unavailable)"
        else:
            mit_text   = mitigation.mitigation
            fixed_code = mitigation.fixed_code

        actionable.append(OWASPVulnerabilityActionable(
            owasp_id          = finding.owasp_id,
            name              = finding.name,
            risk_summary      = finding.risk_summary,
            description       = finding.description,
            evidence          = finding.evidence,
            exploitation_steps= finding.exploitation_steps,
            impact            = finding.impact,
            confidence        = finding.confidence,
            mitigation        = mit_text,
            fixed_code        = fixed_code,
        ))

    return OWASPFunctionReport(vulnerabilities=actionable)


# ── Stage 3: Verification pass ────────────────────────────────────────────────

def _verify_findings(
    all_findings: list[tuple[str, OWASPVulnerabilityActionable, int, int]]
) -> list[tuple[str, OWASPVulnerabilityActionable, int, int]]:
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
            "chunk_lines": f"{chunk_start}-{chunk_end}",
            **vuln.model_dump(
                include={"owasp_id", "name", "risk_summary", "description",
                         "evidence", "exploitation_steps", "impact", "confidence"}
            ),
        }
        for i, (file_path, vuln, chunk_start, chunk_end) in enumerate(all_findings)
    ]

    verifier_prompt = (
        "Review the following list of OWASP findings and decide which to keep.\n"
        "Drop: false positives, findings with impossibly vague evidence, and exact duplicates.\n\n"
        f"Findings (JSON):\n{json.dumps(payload, indent=2)}"
    )

    verification = _invoke_agent(
        agent_verifier, verifier_prompt, VerificationReport, "verifier"
    )

    if verification is None:
        print_warning("Verifier returned no parseable response — keeping all findings as-is.")
        return all_findings

    kept: list[tuple[str, OWASPVulnerabilityActionable, int, int]] = []
    decision_map = {d.index: d for d in verification.decisions}

    for i, (file_path, vuln, chunk_start, chunk_end) in enumerate(all_findings):
        decision = decision_map.get(i)
        if decision is None:
            # No decision → assume keep with original confidence
            kept.append((file_path, vuln, chunk_start, chunk_end))
        elif decision.keep:
            # Apply adjusted confidence
            adjusted = vuln.model_copy(update={"confidence": decision.adjusted_confidence})
            kept.append((file_path, adjusted, chunk_start, chunk_end))
        else:
            print_info(f"Verifier dropped [{i}] {vuln.owasp_id} in {file_path}: {decision.reason}")

    return kept


# ── Aggregation / deduplication ───────────────────────────────────────────────

def _dedup(
    verified: list[tuple[str, OWASPVulnerabilityActionable, int, int]]
) -> list[FinalFinding]:
    """
    Deduplicate by (file, owasp_id, evidence) — keep the entry with the
    highest confidence score.  Returns a flat list of FinalFinding objects.
    """
    best: dict[tuple[str, str, str], tuple[str, OWASPVulnerabilityActionable, int, int]] = {}

    for file_path, vuln, chunk_start, chunk_end in verified:
        key = (file_path, vuln.owasp_id, vuln.evidence)
        if key not in best or vuln.confidence > best[key][1].confidence:
            best[key] = (file_path, vuln, chunk_start, chunk_end)

    return [
        FinalFinding(
            file              = file_path,
            chunk_line_start  = chunk_start,
            chunk_line_end    = chunk_end,
            owasp_id          = v.owasp_id,
            name              = v.name,
            risk_summary      = v.risk_summary,
            description       = v.description,
            evidence          = v.evidence,
            exploitation_steps= v.exploitation_steps,
            impact            = v.impact,
            confidence        = v.confidence,
            mitigation        = v.mitigation,
            fixed_code        = v.fixed_code,
        )
        for file_path, v, chunk_start, chunk_end in best.values()
    ]


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    project_path = sys.argv[1] if len(sys.argv) > 1 else "./project1"

    tasks = get_all_code_tasks(project_path)
    if not tasks:
        print_error(f"No source files found under: {project_path}")
        sys.exit(1)

    print_info(f"Scanning: {project_path}")
    print_info(f"Found {len(tasks)} chunk(s) to analyze across "
               f"{len({t.file for t in tasks})} file(s).")

    # ── Group chunks by file ──────────────────────────────────────────────────
    chunks_by_file: dict[str, list[CodeChunk]] = {}
    for task in tasks:
        chunks_by_file.setdefault(task.file, []).append(task)

    # ── Stages 1 + 2: finder → mitigator (file → chunk) ──────────────────────
    all_findings: list[tuple[str, OWASPVulnerabilityActionable, int, int]] = []
    summary: dict[str, int] = {}

    for file_num, (file_path, file_chunks) in enumerate(chunks_by_file.items(), 1):
        print_header(file_num, len(chunks_by_file), file_path)
        print_info(f"  {len(file_chunks)} chunk(s) in this file")

        for chunk_idx, task in enumerate(file_chunks, 1):
            line_range = f"lines {task.line_start}–{task.line_end}" if task.line_end else f"line {task.line_start}"
            print_info(f"  Chunk {chunk_idx}/{len(file_chunks)}  [{line_range}]")

            try:
                chunk_report = analyze_code_chunk(task)
            except Exception as exc:
                print_error(f"Analysis failed for chunk {chunk_idx} of {file_path}: {exc}")
                continue

            vulns = chunk_report.vulnerabilities
            if not vulns:
                print_success(f"  No vulnerabilities found in chunk {chunk_idx}.")
            else:
                for v in vulns:
                    print_vulnerability(v, task.line_start, task.line_end, file_path)
                    all_findings.append((file_path, v, task.line_start, task.line_end))

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

    if "--report" in sys.argv:
        print(f"\nGenerating professional report: Professional_Vulnerability_Report.docx")
        # Convert list[tuple[file, vuln, start, end]] → dict[file, list[vuln]] as expected by report_generator
        findings_by_file: dict = {}
        for file_path, vuln, _, _ in all_findings:
            findings_by_file.setdefault(file_path, []).append(vuln)
        create_advanced_vuln_report(summary, findings_by_file, "Professional_Vulnerability_Report.docx")
        print("Report generation completed.")

    total = len(final_findings)
    if total > 0:
        print_error(f"{total} verified vulnerability/vulnerabilities detected — blocking deployment.")
        sys.exit(1)
    else:
        print_success("No verified vulnerabilities — safe to deploy.")
        sys.exit(0)
