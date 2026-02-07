from pydantic import BaseModel, Field

class OWASPVulnerability(BaseModel):
    """OWASP vulnerability information."""
    owasp_id: str = Field(description="The OWASP ID of the vulnerability")
    name: str = Field(description="The name of the vulnerability")
    description: str = Field(description="A description of the vulnerability")
    evidence: str = Field(description="Evidence of the vulnerability in the code")
    exploitation_steps: list[str] = Field(description="Steps to exploit the vulnerability")
    impact: str = Field(description="The impact of the vulnerability")
    mitigation: str = Field(description="Mitigation steps for the vulnerability")

class OWASPFunctionReport(BaseModel):
    """Report for a function, including any vulnerabilities found."""
    vulnerabilities: list[OWASPVulnerability] = Field(description="List of vulnerabilities found in the function")

class CodeChunk(BaseModel):
    """Represents a chunk of code to be analyzed."""
    file: str = Field(description="The file path of the code chunk")
    context: str = Field(description="Contextual information about the code chunk (e.g., imports, surrounding code)")
    code_segment: str = Field(description="The actual code segment to analyze")