from langchain.agents import create_agent
from langchain_groq import ChatGroq
from models import OWASPFunctionReport
from prompt import SYSTEM_PROMPT
from config import GROQ_API_KEY, MODEL_NAME, TEMPERATURE

agent_analyzer = create_agent(
    model=ChatGroq(model=MODEL_NAME, temperature=TEMPERATURE, api_key=GROQ_API_KEY),
    system_prompt=SYSTEM_PROMPT,
    response_format=OWASPFunctionReport,
)
