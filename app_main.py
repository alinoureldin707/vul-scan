# app_main.py

from vulnerable_app import login, run_command, deserialize

def test():
    # Example of calling vulnerable functions
    user = "admin"
    password = "' OR '1'='1"
    login(user, password)  # ❌ SQL Injection

    cmd = "ls -la"
    run_command(cmd)       # ❌ Command injection

    data = b"..." 
    deserialize(data)      # ❌ Unsafe deserialization
