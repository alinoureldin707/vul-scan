from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

MODEL_NAME = "llama-3.3-70b-versatile"
TEMPERATURE = 0.0
GROQ_API_KEY = os.getenv("GROQ_API_KEY")