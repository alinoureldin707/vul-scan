# vulnerable_app.py
import sqlite3
API_KEY = "sk_live_123456789"


def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()