import os

API_KEY = "sk_live_123456789"

# vulnerable_app.py
def run_command(cmd):
    # Potential RCE vulnerability
    return os.system(cmd)