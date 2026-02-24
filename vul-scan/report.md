# OWASP Security Scan Report

**Generated:** 2026-02-24T17:32:47Z  
**Scanned path:** `D:\CBRS-503\vul-scan\project2`  
**Files scanned:** 2  
**Chunks analysed:** 5  
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
| A05:2025 | 2 |

### Most Affected Files

| File | Findings |
|------|----------|
| `.\project2\controller.js` | 1 |
| `.\\project2\\service.js` | 1 |

## Summary

| # | File | Chunk Lines | OWASP ID | Name | Confidence |
|---|------|-------------|----------|------|------------|
| 1 | `.\project2\controller.js` | 5-16 | A05:2025 | SQL Injection | 🔴 HIGH (0.92) |
| 2 | `.\\project2\\service.js` | 3-13 | A05:2025 | Command Injection | 🔴 HIGH (0.90) |

## Findings

### 📄 `.\project2\controller.js`

#### [1] A05:2025 — SQL Injection  (Chunk Lines 5-16)

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

**Description:** The username parameter is concatenated into the query string without sanitization.

**Evidence:**
```javascript
const query = `SELECT * FROM users WHERE username = '${username}'`;
```

**Exploitation Steps:**
1. Supply username = ' OR 1=1--
1. Query returns all users
1. Authentication bypassed

**Impact:** Full database access, data breach.

**Fix Recommendation:** Use parameterized queries to prevent SQL injection.

**Fixed Code:**
```javascript
const query = `SELECT * FROM users WHERE username = ?`; db.query(query, [username], (err, results) => { // Fixed: parameterized query })
```

---

### 📄 `.\\project2\\service.js`

#### [2] A05:2025 — Command Injection  (Chunk Lines 3-13)

**Confidence:** 🔴 HIGH (0.90)  

> User input concatenated into command enables code execution.

**Risk Analysis**

| Attribute | Value |
|-----------|-------|
| Severity | 🔴 HIGH |
| Likelihood | 🔴 HIGH |
| Risk Score | **9.0 / 10** |
| Remediation Priority | P1 — Immediate |
| Attack Vector | Injection |

**Description:** The filename parameter is concatenated into the command string without sanitization.

**Evidence:**
```javascript
const command = `cat reports/${filename}`;
```

**Exploitation Steps:**
1. Supply filename = '../etc/passwd'
1. Command returns sensitive system file
1. Information disclosure

**Impact:** Arbitrary file read, potential code execution.

**Fix Recommendation:** Use a child process exec function with separate arguments to prevent command injection.

**Fixed Code:**
```javascript
const childProcess = require('child_process');
const command = 'cat';
const args = ['reports/' + filename];
childProcess.execFile(command, args, (error, stdout, stderr) => {
  // Fixed: use execFile with separate args
  if (error) {
    console.error(`Error: ${error.message}`);
    return;
  }
  console.log(`Report output:\n${stdout}`);
});
```

---
