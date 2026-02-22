from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

MODEL_NAME = os.getenv("MODEL_NAME", "llama-3.3-70b-versatile")
TEMPERATURE = float(os.getenv("TEMPERATURE", "0.0"))
MAX_TOKENS = int(os.getenv("MAX_TOKENS", "8192"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
GROQ_API_KEY = os.getenv("GROQ_API_KEY")