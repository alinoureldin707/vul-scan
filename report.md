# OWASP Security Scan Report

**Generated:** 2026-02-21T17:47:21Z  
**Scanned path:** `C:\Users\User\Desktop\CBRS503-project\project1`  
**Files scanned:** 3  
**Chunks analysed:** 3  
**Total findings:** 1  

## Risk Analysis

**Overall Risk Level:** 🔴 **HIGH**

### Severity Breakdown

| Severity | Count |
|----------|-------|
| 🔴 High   | 1 |
| 🟠 Medium | 0 |
| 🟡 Low    | 0 |

### OWASP Category Distribution

| OWASP ID | Findings |
|----------|----------|
| A02:2025 | 1 |

### Most Affected Files

| File | Findings |
|------|----------|
| `./project1\database.js` | 1 |

## Summary

| # | File | OWASP ID | Name | Lines | Confidence |
|---|------|----------|------|-------|------------|
| 1 | `./project1\database.js` | A02:2025 | Hardcoded Credentials | lines 4–8 | 🔴 HIGH (0.99) |

## Findings

### 📄 `./project1\database.js`

#### [1] A02:2025 — Hardcoded Credentials

**Location:** lines 4–8  
**Confidence:** 🔴 HIGH (0.99)  

> Hardcoded database credentials in source code expose the database to anyone who can read the code, enabling unauthorized access and potential data compromise.

**Risk Analysis**

| Attribute | Value |
|-----------|-------|
| Severity | 🔴 HIGH |
| Likelihood | 🔴 HIGH |
| Risk Score | **9.9 / 10** |
| Remediation Priority | P1 — Immediate |
| Attack Vector | Cryptographic Failure |

**Description:** The code creates a MySQL connection using hardcoded host, user, password, and database values, including an empty password for the root user. This configuration allows anyone with access to the source to obtain valid credentials and connect to the database.

**Evidence:**
```
const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "vulnapp"
});
```

**Exploitation Steps:**
1. Step 1: Attacker reads the source code to discover the hardcoded credentials.
1. Step 2: Attacker uses the credentials to establish a connection to the MySQL database.
1. Step 3: Attacker can read, modify, or delete data in the database.

**Impact:** Unauthorized database access can lead to data theft, tampering, or destruction, compromising application integrity and confidentiality.

**Fix Recommendation (lines 4–8):** Replace hardcoded database credentials with environment variables. Store credentials in a secure .env file or secret manager and load them via process.env. Avoid committing sensitive data to source control.

**Fixed Code:**
```python
const mysql = require("mysql");

// ✅ Use environment variables for credentials
const connection = mysql.createConnection({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "vulnapp"
});

connection.connect();

module.exports = connection;
```

---
