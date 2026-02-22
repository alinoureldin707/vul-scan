# OWASP Security Scan Report

**Generated:** 2026-02-22T18:17:12Z  
**Scanned path:** `D:\CBRS-503\vul-scan\project`  
**Files scanned:** 4  
**Chunks analysed:** 6  
**Total findings:** 3  

## Risk Analysis

**Overall Risk Level:** 🔴 **CRITICAL**

### Severity Breakdown

| Severity | Count |
|----------|-------|
| 🔴 High   | 3 |
| 🟠 Medium | 0 |
| 🟡 Low    | 0 |

### OWASP Category Distribution

| OWASP ID | Findings |
|----------|----------|
| A05:2025 | 2 |
| A04:2025 | 1 |

### Most Affected Files

| File | Findings |
|------|----------|
| `./project\test.js` | 1 |
| `./project\test.ts` | 1 |
| `./project\vulnerable_app.py` | 1 |

## Summary

| # | File | Chunk Lines | OWASP ID | Name | Confidence |
|---|------|-------------|----------|------|------------|
| 1 | `./project\test.js` | 1-12 | A05:2025 | Command Injection | 🔴 HIGH (0.92) |
| 2 | `./project\test.ts` | 1-10 | A04:2025 | Hardcoded Secret | 🔴 HIGH (0.95) |
| 3 | `./project\vulnerable_app.py` | 6-11 | A05:2025 | SQL Injection | 🔴 HIGH (0.92) |

## Findings

### 📄 `./project\test.js`

#### [1] A05:2025 — Command Injection  (Chunk Lines 1-12)

**Confidence:** 🔴 HIGH (0.92)  

> User input concatenated into system commands enables code execution and data breaches.

**Risk Analysis**

| Attribute | Value |
|-----------|-------|
| Severity | 🔴 HIGH |
| Likelihood | 🔴 HIGH |
| Risk Score | **9.2 / 10** |
| Remediation Priority | P1 — Immediate |
| Attack Vector | Injection |

**Description:** The run_command function is vulnerable to command injection attacks, allowing an attacker to execute arbitrary system commands.

**Evidence:**
```javascript
return require("child_process").execSync(cmd).toString();
```

**Exploitation Steps:**
1. Supply cmd = "ls -l"
1. Command is executed on the system
1. Sensitive files and directories are exposed

**Impact:** Arbitrary code execution, sensitive data exposure.

**Fix Recommendation:** Use a safer alternative to execSync, such as spawn, and validate or escape user input to prevent command injection.

**Fixed Code:**
```javascript
const { spawn } = require('child_process');
const child = spawn(cmd, { shell: true });
let result = '';
child.stdout.on('data', (data) => {
  result += data.toString();
});
// Fixed: use spawn and handle output safely
return new Promise((resolve) => {
  child.on('close', () => {
    resolve(result);
  });
});
```

---

### 📄 `./project\test.ts`

#### [2] A04:2025 — Hardcoded Secret  (Chunk Lines 1-10)

**Confidence:** 🔴 HIGH (0.95)  

> API key is hardcoded in the code, enabling unauthorized access.

**Risk Analysis**

| Attribute | Value |
|-----------|-------|
| Severity | 🔴 HIGH |
| Likelihood | 🔴 HIGH |
| Risk Score | **9.5 / 10** |
| Remediation Priority | P1 — Immediate |
| Attack Vector | Cryptographic Failure |

**Description:** The API key is directly written in the code without any encryption or secure storage.

**Evidence:**
```typescript
const API_KEY = "sk_live_123456789";
```

**Exploitation Steps:**
1. Access the code
1. Extract the API key
1. Use the API key for malicious purposes

**Impact:** Unauthorized access to the API, potential data breach.

**Fix Recommendation:** Load secret from environment variable instead of hardcoding.

**Fixed Code:**
```typescript
const API_KEY = process.env.API_KEY; // Fixed: use env var
```

---

### 📄 `./project\vulnerable_app.py`

#### [3] A05:2025 — SQL Injection  (Chunk Lines 6-11)

**Confidence:** 🔴 HIGH (0.92)  

> User input concatenated into SQL query enables data exfiltration.

**Risk Analysis**

| Attribute | Value |
|-----------|-------|
| Severity | 🔴 HIGH |
| Likelihood | 🔴 HIGH |
| Risk Score | **9.2 / 10** |
| Remediation Priority | P1 — Immediate |
| Attack Vector | Injection |

**Description:** The username and password parameters are concatenated into the query string without sanitization.

**Evidence:**
```python
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
```

**Exploitation Steps:**
1. Supply username = ' OR 1=1--
1. Query returns all users
1. Authentication bypassed

**Impact:** Full database access, data breach.

**Fix Recommendation:** Use parameterized queries to prevent SQL injection.

**Fixed Code:**
```python
import sqlite3
query = "SELECT * FROM users WHERE username=? AND password=?"
params = (username, password)
cursor.execute(query, params) # Fixed: parameterized query
```

---
