from dotenv import load_dotenv
import os
import sys

# Load environment variables from .env file
load_dotenv()

MODEL_NAME = os.getenv("MODEL_NAME", "llama-3.3-70b-versatile")
TEMPERATURE = float(os.getenv("TEMPERATURE", "0.0"))
MAX_TOKENS = int(os.getenv("MAX_TOKENS", "8192"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Validate required configuration
if not GROQ_API_KEY:
    print("\033[91m✖ Error: GROQ_API_KEY environment variable is not set.\033[0m")
    print("  Please set it in your .env file or environment:")
    print("    GROQ_API_KEY=your_api_key_here")
    sys.exit(1)