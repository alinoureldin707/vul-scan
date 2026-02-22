# OWASP Security Scan Report

**Generated:** 2026-02-22T11:55:10Z  
**Scanned path:** `C:\Users\User\Desktop\CBRS503-project\project1`  
**Files scanned:** 3  
**Chunks analysed:** 3  
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
| A05:2025 | 1 |
| A04:2025 | 1 |

### Most Affected Files

| File | Findings |
|------|----------|
| `./project1\app.js` | 1 |
| `./project1\server.js` | 1 |

## Summary

| # | File | OWASP ID | Name | Lines | Confidence |
|---|------|----------|------|-------|------------|
| 1 | `./project1\app.js` | A05:2025 | Code Injection via eval | line 10 | 🔴 HIGH (0.99) |
| 2 | `./project1\server.js` | A04:2025 | Weak Hash Algorithm | lines 1–3 | 🔴 HIGH (0.99) |

## Findings

### 📄 `./project1\app.js`

#### [1] A05:2025 — Code Injection via eval

**Location:** line 10  
**Confidence:** 🔴 HIGH (0.99)  

> Using eval on user-supplied input allows an attacker to execute arbitrary JavaScript on the server. This can lead to full compromise of the application, including data exfiltration, privilege escalation, or denial of service.

**Risk Analysis**

| Attribute | Value |
|-----------|-------|
| Severity | 🔴 HIGH |
| Likelihood | 🔴 HIGH |
| Risk Score | **9.9 / 10** |
| Remediation Priority | P1 — Immediate |
| Attack Vector | Security Misconfiguration |

**Description:** The endpoint /calculate accepts a 'formula' field from the request body and passes it directly to JavaScript's eval without validation or sanitisation. eval executes the string as code in the server's context, giving the attacker full control over the runtime environment.

**Evidence:**
```
const result = eval(formula);
```

**Exploitation Steps:**
1. Send a POST request to /calculate with JSON body {"formula": "process.exit(0);"}
1. The server executes process.exit(0) via eval, terminating the process
1. The attacker can inject any JavaScript code, including reading files, spawning processes, or modifying server state

**Impact:** Arbitrary code execution on the server, enabling data theft, privilege escalation, or service disruption.

**Fix Recommendation (lines 10–12):** Validate and sanitize the 'formula' input to allow only numeric and arithmetic characters before evaluating. Reject any input that contains disallowed characters and return a 400 error. This prevents arbitrary code execution via eval.

**Fixed Code:**
```python
import * as express from "express";

const app = express();
app.use(express.json());

app.post("/calculate", (req, res) => {
    const formula = req.body.formula;

    // ✅ Safe evaluation: allow only numbers and arithmetic operators
    let result;
    try {
        const safe = formula.replace(/[\^\d+\-*/().\s]/g, '');
        if (!/^[0-9+\-*/().\s]+$/.test(safe)) throw new Error('Invalid formula');
        result = eval(safe);
    } catch (e) {
        return res.status(400).send({ error: e.message });
    }

    res.send({ result });
});

app.post("/deserialize", (req, res) => {
    const data = req.body.data;

    // ❌ Insecure deserialization
    const obj = JSON.parse(data);

    res.send(obj);
});

app.listen(4000, () => {
    console.log("App running on port 4000");
});
```

---

### 📄 `./project1\server.js`

#### [2] A04:2025 — Weak Hash Algorithm

**Location:** lines 1–3  
**Confidence:** 🔴 HIGH (0.99)  

> Using MD5 for password hashing is insecure because MD5 is vulnerable to collision and brute‑force attacks, allowing attackers to recover plaintext passwords from stored hashes.

**Risk Analysis**

| Attribute | Value |
|-----------|-------|
| Severity | 🔴 HIGH |
| Likelihood | 🔴 HIGH |
| Risk Score | **9.9 / 10** |
| Remediation Priority | P1 — Immediate |
| Attack Vector | Insecure Design / Misconfiguration |

**Description:** The function hashPassword hashes passwords using crypto.createHash("md5"), which is a weak algorithm unsuitable for password storage.

**Evidence:**
```
return crypto.createHash("md5").update(password).digest("hex");
```

**Exploitation Steps:**
1. Step 1: Attacker obtains the stored MD5 hash of a password.
1. Step 2: Attacker uses precomputed rainbow tables or brute‑force to reverse the hash.
1. Step 3: Attacker recovers the plaintext password and gains unauthorized access.

**Impact:** Compromised user accounts and potential data breach due to easy password recovery.

**Fix Recommendation (lines 1–3):** Replace the insecure MD5 hash with a strong, adaptive key derivation function such as PBKDF2 (or bcrypt/argon2). Generate a random salt for each password, derive a key with a high iteration count, and store both the salt and hash together (e.g., as "salt:hash"). This prevents pre‑computed rainbow table attacks and makes brute‑force attempts computationally expensive.

**Fixed Code:**
```python
function hashPassword(password) {
    // Generate a random 16‑byte salt
    const salt = crypto.randomBytes(16);
    // Derive a 64‑byte key using PBKDF2 with 100,000 iterations and SHA‑512
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');
    // Return the salt and hash concatenated with a separator for storage
    return `${salt.toString('hex')}:${hash.toString('hex')}`;
}
```

---
