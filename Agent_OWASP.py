import json
import re
from typing import List
from pydantic import BaseModel
from langchain_groq import ChatGroq

MODEL_NAME = "llama-3.1-8b-instant"
TEMPERATURE = 0

SYSTEM_PROMPT = """
You are an Application Security expert.

Analyze the given code chunk and detect vulnerabilities ONLY from the OWASP Top 10 (2025) categories listed below. Do NOT invent new categories.

If the code does not contain any vulnerabilities from this list, output EXACTLY:
{ "vulnerabilities": [] }

OWASP Top 10 (2025) Categories:

A01:2025 - Broken Access Control
Description: Missing or weak authorization checks allow users to access data or actions they should not.

A02:2025 - Security Misconfiguration
Description: Unsafe default settings, unnecessary services, debug mode, or incorrect security headers/configurations.

A03:2025 - Software Supply Chain Failures
Description: Using vulnerable libraries, dependencies, or untrusted components that compromise security.

A04:2025 - Cryptographic Failures
Description: Weak, missing, or incorrect encryption/hashing exposes sensitive data or credentials.

A05:2025 - Injection
Description: Untrusted input is executed as commands or queries (SQL injection, command injection, LDAP injection, etc.).

A06:2025 - Insecure Design
Description: Security is not designed into the system, resulting in architectural weaknesses or missing protections.

A07:2025 - Authentication Failures
Description: Weak login/session handling (no MFA, weak passwords, session fixation, insecure cookies, etc.).

A08:2025 - Software or Data Integrity Failures
Description: Missing integrity checks for updates or data, unsafe deserialization, or untrusted CI/CD pipelines.

A09:2025 - Security Logging and Alerting Failures
Description: Missing logs or alerts make attacks harder to detect and respond to.

A10:2025 - Mishandling of Exceptional Conditions
Description: Improper handling of errors, exceptions, or unexpected conditions that expose sensitive information or leave the system in an insecure state.

OUTPUT FORMAT RULES (MANDATORY):
- Output MUST be valid JSON
- Output JSON ONLY (no markdown, no explanations)
- Each vulnerability MUST be unique
- Exploitation steps MUST be sequential, concrete, and realistic
- Impact MUST be specific to that vulnerability
- Mitigation MUST be specific to that vulnerability
- Do NOT reuse the same impact or mitigation text across vulnerabilities

JSON SCHEMA (EXACT):

{
  "vulnerabilities": [
    {
      "owasp_id": "A03:2025",
      "name": "Injection",
      "description": "Explain what the vulnerability is in this code chunk.",
      "evidence": "Quote the exact risky line(s) or behavior from the code chunk.",
      "exploitation_steps": [
        "Step 1: ...",
        "Step 2: ...",
        "Step 3: ..." (write all the steps for doing the exploitation)
      ],
      "impact": "Explain the direct real-world impact.",
      "mitigation": "Explain the best fix for THIS exact code."
    }
  ]
}

"""

# ----------------------------
# Pydantic Response Models
# ----------------------------

class OWASPVulnerability(BaseModel):
    owasp_id: str
    name: str
    description: str
    evidence: str
    exploitation_steps: List[str]
    impact: str
    mitigation: str

class OWASPFunctionReport(BaseModel):
    vulnerabilities: List[OWASPVulnerability]


# ----------------------------
# Analyzer (Direct LLM Call)
# ----------------------------

class OWASPFunctionAnalyzer:
    def __init__(self):
        self.model = ChatGroq(
            model=MODEL_NAME,
            temperature=TEMPERATURE,
        )

    def analyze(self, code_chunk: str) -> OWASPFunctionReport:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Analyze this code:\n\n{code_chunk}"}
        ]

        response = self.model.invoke(messages)

        raw_output = response.content.strip()

        # Print RAW output like you want
        print(raw_output)

        # Extract JSON object from model output
        match = re.search(r"\{[\s\S]*\}", raw_output)
        if not match:
            raise ValueError(f"No JSON found in model output:\n{raw_output}")

        json_text = match.group(0)

        # Fix common JSON mistakes (optional but useful)
        json_text = json_text.replace("“", "\"").replace("”", "\"").replace("’", "'")

        parsed = json.loads(json_text)

        return OWASPFunctionReport.model_validate(parsed)


# ----------------------------
# Run test chunks
# ----------------------------

if __name__ == "__main__":
    analyzer = OWASPFunctionAnalyzer()

    code_chunks = [
        """
import subprocess

def run_command(cmd):
    return subprocess.check_output(cmd, shell=True)
""",
        """
import sqlite3

DB_PATH = "app.db"

def get_user(username):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()
""",
        """
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
""",
        """
import os
import sqlite3
import hashlib
import subprocess

DB_PATH = "app.db"

def process_user(username, password, cmd):
    # SQL Injection
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)

    # Weak password hashing
    password_hash = hashlib.md5(password.encode()).hexdigest()

    # Command Injection
    output = subprocess.check_output(cmd, shell=True)

    # Insecure file access
    with open(f"/tmp/{username}.txt", "w") as f:
        f.write(password_hash)

    return output
"""
    ]

    for idx, chunk in enumerate(code_chunks, 1):
        print(f"\nAnalyzing Function Chunk {idx}")
        print("-" * 60)

        try:
            report = analyzer.analyze(chunk)

            # This prints the JSON output you want
            print(report.model_dump_json(indent=2))

        except Exception as e:
            print(f"Error analyzing chunk {idx}: {e}")

        print("-" * 60)
