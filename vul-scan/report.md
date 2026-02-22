# OWASP Security Scan Report

**Generated:** 2026-02-22T16:47:18Z  
**Scanned path:** `D:\CBRS-503\project2`  
**Files scanned:** 3  
**Chunks analysed:** 5  
**Total findings:** 4  

## Risk Analysis

**Overall Risk Level:** 🔴 **CRITICAL**

### Severity Breakdown

| Severity | Count |
|----------|-------|
| 🔴 High   | 4 |
| 🟠 Medium | 0 |
| 🟡 Low    | 0 |

### OWASP Category Distribution

| OWASP ID | Findings |
|----------|----------|
| A04:2025 | 2 |
| A07:2025 | 2 |

### Most Affected Files

| File | Findings |
|------|----------|
| `.\project2\authConfig.js` | 2 |
| `.\project2\authService.js` | 2 |

## Summary

| # | File | Chunk Lines | OWASP ID | Name | Confidence |
|---|------|-------------|----------|------|------------|
| 1 | `.\project2\authConfig.js` | 2-8 | A04:2025 | Hardcoded Secrets | 🔴 HIGH (0.95) |
| 2 | `.\project2\authConfig.js` | 2-8 | A07:2025 | Weak Password Handling | 🔴 HIGH (0.95) |
| 3 | `.\project2\authService.js` | 4-20 | A04:2025 | Hardcoded Secret | 🔴 HIGH (0.95) |
| 4 | `.\project2\authService.js` | 4-20 | A07:2025 | Weak Password Handling | 🔴 HIGH (0.95) |

## Findings

### 📄 `.\project2\authConfig.js`

#### [1] A04:2025 — Hardcoded Secrets  (Chunk Lines 2-8)

**Confidence:** 🔴 HIGH (0.95)  

> Hardcoded secret key enables unauthorized access.

**Risk Analysis**

| Attribute | Value |
|-----------|-------|
| Severity | 🔴 HIGH |
| Likelihood | 🟠 MEDIUM |
| Risk Score | **5.7 / 10** |
| Remediation Priority | P2 — High Priority |
| Attack Vector | Cryptographic Failure |

**Description:** The secret key is hardcoded in the authConfig.js file.

**Evidence:**
```javascript
secretKey: "simple_secret_key"
```

**Exploitation Steps:**
1. Access the authConfig.js file
1. Obtain the secret key

**Impact:** Unauthorized access to sensitive data.

**Fix Recommendation:** Load secret from environment variable instead of hardcoding.

**Fixed Code:**
```javascript
const secretKey = process.env.SECRET_KEY; // Fixed: use env var
```

---

#### [2] A07:2025 — Weak Password Handling  (Chunk Lines 2-8)

**Confidence:** 🔴 HIGH (0.95)  

> Hardcoded user passwords enable unauthorized access.

**Risk Analysis**

| Attribute | Value |
|-----------|-------|
| Severity | 🔴 HIGH |
| Likelihood | 🟠 MEDIUM |
| Risk Score | **5.7 / 10** |
| Remediation Priority | P2 — High Priority |
| Attack Vector | Authentication Failure |

**Description:** The user passwords are hardcoded in the authConfig.js file.

**Evidence:**
```javascript
password: "admin123"
```

**Exploitation Steps:**
1. Access the authConfig.js file
1. Obtain the user passwords

**Impact:** Unauthorized access to user accounts.

**Fix Recommendation:** Load passwords from a secure storage and hash them before comparison. Use environment variables or a secrets manager to store sensitive data.

**Fixed Code:**
```javascript
const bcrypt = require('bcrypt');
const hashedPassword = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
module.exports = {
  secretKey: process.env.SECRET_KEY,
  users: [
    { username: "admin", password: hashedPassword, role: "ADMIN" },
    { username: "user", password: bcrypt.hashSync(process.env.USER_PASSWORD, 10), role: "USER" },
  ],
}; // Fixed: use env vars and hash passwords
```

---

### 📄 `.\project2\authService.js`

#### [3] A04:2025 — Hardcoded Secret  (Chunk Lines 4-20)

**Confidence:** 🔴 HIGH (0.95)  

> Hardcoded secret key enables unauthorized access.

**Risk Analysis**

| Attribute | Value |
|-----------|-------|
| Severity | 🔴 HIGH |
| Likelihood | 🟠 MEDIUM |
| Risk Score | **5.7 / 10** |
| Remediation Priority | P2 — High Priority |
| Attack Vector | Cryptographic Failure |

**Description:** The secretKey is hardcoded in the authConfig file.

**Evidence:**
```javascript
const { users, secretKey } = require("../config/authConfig");
```

**Exploitation Steps:**
1. Access the authConfig file
1. Extract the secretKey

**Impact:** Unauthorized access to sensitive data.

**Fix Recommendation:** (unavailable)

**Fixed Code:**
```javascript
(unavailable)
```

---

#### [4] A07:2025 — Weak Password Handling  (Chunk Lines 4-20)

**Confidence:** 🔴 HIGH (0.95)  

> Passwords are stored in plaintext.

**Risk Analysis**

| Attribute | Value |
|-----------|-------|
| Severity | 🔴 HIGH |
| Likelihood | 🟠 MEDIUM |
| Risk Score | **5.7 / 10** |
| Remediation Priority | P2 — High Priority |
| Attack Vector | Authentication Failure |

**Description:** The passwords are stored in plaintext in the users array.

**Evidence:**
```javascript
u.password === password
```

**Exploitation Steps:**
1. Access the users array
1. Extract the passwords

**Impact:** Unauthorized access to user accounts.

**Fix Recommendation:** (unavailable)

**Fixed Code:**
```javascript
(unavailable)
```

---
