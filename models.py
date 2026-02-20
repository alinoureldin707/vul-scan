from pydantic import BaseModel, Field


# ── Stage 1: Finder agent output ─────────────────────────────────────────────

class OWASPVulnerabilityFinding(BaseModel):
    """A detected vulnerability — no mitigation yet."""

    owasp_id: str = Field(description="The OWASP Top-10 ID, e.g. A05:2025")
    name: str = Field(description="Short vulnerability name")
    risk_summary: str = Field(description="2-3 sentence plain-language summary of the risk")
    description: str = Field(description="Why this code is insecure")
    evidence: str = Field(description="Exact lines or constructs causing the issue")
    line_start: int = Field(default=0, description="First 1-based line number of the vulnerable code")
    line_end: int = Field(default=0, description="Last 1-based line number of the vulnerable code")
    exploitation_steps: list[str] = Field(description="Ordered steps an attacker would follow")
    impact: str = Field(description="Concrete real-world damage this enables")
    confidence: float = Field(default=0.9, ge=0.0, le=1.0, description="Confidence score 0.0–1.0")


class OWASPFindingReport(BaseModel):
    """Output of the finder agent for a single code chunk."""

    vulnerabilities: list[OWASPVulnerabilityFinding] = Field(
        description="All confirmed vulnerabilities in this chunk"
    )


# ── Stage 2: Mitigation agent output ─────────────────────────────────────────

class VulnerabilityMitigation(BaseModel):
    """Actionable mitigation for a single vulnerability."""

    mitigation: str = Field(description="Clear, code-level recommendation to fix the vulnerability")
    fix_line_start: int = Field(default=0, description="First 1-based line number where the fix should be applied")
    fix_line_end: int = Field(default=0, description="Last 1-based line number where the fix should be applied")
    fixed_code: str = Field(description="A complete, corrected version of the vulnerable code segment")


# ── Stage 3: Verifier agent output ───────────────────────────────────────────

class VerificationDecision(BaseModel):
    """Keep/drop decision for one finding produced by the verifier agent."""

    index: int = Field(description="0-based index of the finding in the submitted list")
    keep: bool = Field(description="True if the finding is a confirmed real vulnerability")
    adjusted_confidence: float = Field(default=0.9, ge=0.0, le=1.0, description="Revised confidence after review")
    reason: str = Field(description="One sentence justifying the decision")


class VerificationReport(BaseModel):
    """Output of the verifier agent — one decision per submitted finding."""

    decisions: list[VerificationDecision]


# ── Combined per-chunk result ─────────────────────────────────────────────────

class OWASPVulnerabilityActionable(BaseModel):
    """A vulnerability finding enriched with its mitigation and fixed code."""

    owasp_id: str
    name: str
    risk_summary: str = ""
    description: str
    evidence: str
    line_start: int = 0
    line_end: int = 0
    exploitation_steps: list[str]
    impact: str
    confidence: float = 0.9
    mitigation: str
    fix_line_start: int = 0
    fix_line_end: int = 0
    fixed_code: str


class OWASPFunctionReport(BaseModel):
    """Final report for a code chunk: findings + mitigations."""

    vulnerabilities: list[OWASPVulnerabilityActionable] = Field(
        description="Vulnerabilities with actionable fixes"
    )


# ── Aggregated scan output ────────────────────────────────────────────────────

class FinalFinding(BaseModel):
    """A single verified, deduplicated finding with full file context."""

    file: str
    owasp_id: str
    name: str
    risk_summary: str
    description: str
    evidence: str
    line_start: int = 0
    line_end: int = 0
    exploitation_steps: list[str]
    impact: str
    confidence: float = 0.9
    mitigation: str
    fix_line_start: int = 0
    fix_line_end: int = 0
    fixed_code: str


class FinalReport(BaseModel):
    """Complete scan result written to report.json and report.md."""

    scanned_path: str
    total_files: int
    total_chunks: int
    total_findings: int
    findings: list[FinalFinding]


# ── Splitter output ───────────────────────────────────────────────────────────

class CodeChunk(BaseModel):
    """Represents a chunk of code to be analyzed."""

    file: str = Field(description="The file path of the code chunk")
    context: str = Field(description="Contextual information about the code chunk (e.g., imports, surrounding code)")
    code_segment: str = Field(description="The actual code segment to analyze")


class CodeChunkList(BaseModel):
    """A list of code chunks extracted from a single file by the splitter agent."""

    chunks: list[CodeChunk] = Field(description="Ordered list of code chunks extracted from the file")
