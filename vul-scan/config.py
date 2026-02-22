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
    print("\033[91m✖ Error: GROQ_API_KEY is not set.\033[0m")
    print("  Provide it in one of three ways:")
    print("    1. CLI flag:      vulnerability-scan ./project --api-key gsk_...")
    print("    2. .env file:     GROQ_API_KEY=gsk_...  (in your project folder)")
    print("    3. Env variable:  set GROQ_API_KEY=gsk_...  (Windows)")
    print("                      export GROQ_API_KEY=gsk_...  (Linux/macOS)")
    sys.exit(1)