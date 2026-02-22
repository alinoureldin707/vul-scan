from flask import Flask, request
import sqlite3

app = Flask(__name__)

# ❌ Hardcoded secret (SonarQube will flag this)
app.secret_key = "SUPER_SECRET_KEY_123"

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # ❌ SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)

    user = cursor.fetchone()
    conn.close()

    if user:
        return "Login successful"
    return "Invalid credentials"

if __name__ == "__main__":
    app.run(debug=True)  # ❌ Debug mode enabled (security risk)