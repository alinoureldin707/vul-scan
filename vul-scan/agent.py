from langchain.agents import create_agent
from langchain_groq import ChatGroq
from .models import OWASPFindingReport, VulnerabilityMitigation, VerificationReport, CodeChunkList
from .prompt import FINDER_SYSTEM_PROMPT, MITIGATION_SYSTEM_PROMPT, VERIFIER_SYSTEM_PROMPT, SPLITTER_SYSTEM_PROMPT
from .config import GROQ_API_KEY, MODEL_NAME, TEMPERATURE, MAX_TOKENS


def _create_model(temperature: float = TEMPERATURE) -> ChatGroq:
    """Create a ChatGroq model with consistent configuration."""
    return ChatGroq(
        model=MODEL_NAME,
        temperature=temperature,
        api_key=GROQ_API_KEY,
        max_tokens=MAX_TOKENS,
    )


# Stage 1: splits source files into logical code chunks
agent_splitter = create_agent(
    model=_create_model(temperature=0.0),
    system_prompt=SPLITTER_SYSTEM_PROMPT,
    response_format=CodeChunkList,
)

# Stage 2: finds vulnerabilities (no mitigation)
agent_finder = create_agent(
    model=_create_model(),
    system_prompt=FINDER_SYSTEM_PROMPT,
    response_format=OWASPFindingReport,
)

# Stage 3: produces mitigation + fixed code for a single finding
agent_mitigator = create_agent(
    model=_create_model(),
    system_prompt=MITIGATION_SYSTEM_PROMPT,
    response_format=VulnerabilityMitigation,
)

# Stage 4: validates findings, drops false positives/duplicates, adjusts confidence
agent_verifier = create_agent(
    model=_create_model(temperature=0.0),
    system_prompt=VERIFIER_SYSTEM_PROMPT,
    response_format=VerificationReport,
)