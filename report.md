# OWASP Security Scan Report

**Generated:** 2026-02-20T19:54:05Z  
**Scanned path:** `D:\CBRS-503\project`  
**Files scanned:** 4  
**Chunks analysed:** 4  
**Total findings:** 2  

## Risk Analysis

**Overall Risk Level:** 🔴 **HIGH**

### Severity Breakdown

| Severity | Count |
|----------|-------|
| 🔴 High   | 2 |
| 🟠 Medium | 0 |
| 🟡 Low    | 0 |

### OWASP Category Distribution

| OWASP ID | Findings |
|----------|----------|
| A04:2025 | 1 |
| A05:2025 | 1 |

### Most Affected Files

| File | Findings |
|------|----------|
| `./project\test.js` | 1 |
| `./project\vulnerable_app.py` | 1 |

## Summary

| # | File | OWASP ID | Name | Lines | Confidence |
|---|------|----------|------|-------|------------|
| 1 | `./project\test.js` | A04:2025 | Hardcoded Secret | line 5 | 🔴 HIGH (0.99) |
| 2 | `./project\vulnerable_app.py` | A05:2025 | SQL Injection | lines 2–5 | 🔴 HIGH (0.99) |

## Findings

### 📄 `./project\test.js`

#### [1] A04:2025 — Hardcoded Secret

**Location:** line 5  
**Confidence:** 🔴 HIGH (0.99)  

> A hardcoded API key is embedded in the source code, exposing sensitive credentials to anyone with repository access. This can lead to unauthorized API usage and potential data compromise.

**Risk Analysis**

| Attribute | Value |
|-----------|-------|
| Severity | 🔴 HIGH |
| Likelihood | 🔴 HIGH |
| Risk Score | **9.9 / 10** |
| Remediation Priority | P1 — Immediate |
| Attack Vector | Insecure Design / Misconfiguration |

**Description:** The API_KEY constant is assigned a literal string containing a live API key. This key is not stored securely or rotated, making it vulnerable to theft.

**Evidence:**
```
const API_KEY = "sk_live_123456789";
```

**Exploitation Steps:**
1. Read the source code to obtain the API_KEY
1. Use the key to authenticate to the external API and perform privileged actions
1. Potentially exfiltrate data or perform unauthorized operations

**Impact:** An attacker who gains access to the repository can use the exposed API key to access the external service, potentially leading to data exfiltration, unauthorized actions, or service abuse.

**Fix Recommendation (line 5):** Replace the hardcoded API key with an environment variable or secure vault reference. Update the code to read the key from process.env.API_KEY (or a configuration service) and remove the literal value from the source. This prevents the key from being exposed in the repository and allows rotation without code changes.

**Fixed Code:**
```python
export const test = () => {\n  // vulnerable_app\n  const sqlite3 = require(\"sqlite3\").verbose();\n  const fs = require(\"fs\");\n  const API_KEY = process.env.API_KEY || \"\"; // Use environment variable for API key\n\n  // vulnerable_app\n  function run_command(cmd) {\n    // Potential RCE vulnerability\n    return require(\"child_process\").execSync(cmd).toString();\n  }\n};
```

---

### 📄 `./project\vulnerable_app.py`

#### [2] A05:2025 — SQL Injection

**Location:** lines 2–5  
**Confidence:** 🔴 HIGH (0.99)  

> User-supplied credentials are concatenated into a SQL query without sanitisation, allowing attackers to inject arbitrary SQL and bypass authentication or exfiltrate data.

**Risk Analysis**

| Attribute | Value |
|-----------|-------|
| Severity | 🔴 HIGH |
| Likelihood | 🔴 HIGH |
| Risk Score | **9.9 / 10** |
| Remediation Priority | P1 — Immediate |
| Attack Vector | Security Misconfiguration |

**Description:** The login function builds a SQL statement using an f-string that directly interpolates the username and password parameters, then executes it with sqlite3. This permits an attacker to craft input that alters the query logic.

**Evidence:**
```
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
cursor.execute(query)
```

**Exploitation Steps:**
1. Supply username = "' OR '1'='1" and any password
1. The query becomes SELECT * FROM users WHERE username='' OR '1'='1' AND password='...' which always evaluates to true
1. cursor.fetchone() returns the first user record, granting unauthorized access

**Impact:** An attacker can bypass authentication, read or modify any user data, and potentially execute further destructive SQL commands.

**Fix Recommendation (lines 2–5):** Replace the f-string SQL construction with a parameterized query using sqlite3’s placeholder syntax to prevent SQL injection. This ensures user input is treated as data, not executable code.

**Fixed Code:**
```python
def login(username, password):
    # Use a parameterized query to avoid SQL injection
    query = "SELECT * FROM users WHERE username=? AND password=?"
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(query, (username, password))
    return cursor.fetchone()
```

---
