from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

MODEL_NAME = "openai/gpt-oss-20b"
TEMPERATURE = 0.0
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
