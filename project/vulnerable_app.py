# vulnerable_app.py

import os
import sqlite3

API_KEY = "sk_live_123456789"

def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()

def run_command(cmd):
    return os.system(cmd)

def deserialize(data):
    import pickle
    return pickle.loads(data)
