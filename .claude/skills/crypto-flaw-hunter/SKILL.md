---
name: crypto-flaw-hunter
description: "Audits observed cryptographic artifacts (TLS configuration evidence from prior scans, encrypted cookies / tokens, JWT algorithm choices, padding-oracle candidates) for weak primitives, missing authenticated encryption, hardcoded key patterns in recon data, bit-flipping susceptibility, and unencrypted transmission of sensitive data. Passive-only — this skill analyzes artifacts other skills captured rather than actively scanning. Use after web-recon-active / api-recon have collected response headers and cookies; or after secrets-in-code-hunter surfaces key-like strings. Produces findings with CWE-327 / CWE-319 / CWE-326 mapping and cipher / protocol hardening remediation."
model: opus
allowed-tools: Read, Grep, Glob, WebFetch(domain:*.in-scope-domain.com)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: cross-cutting
  authorization_required: true
  tier: T2
  source_methodology: "Guia de Testes e Mitigação de Falhas Criptográficas.md"
  service_affecting: false
  composed_from: []
---

# Crypto Flaw Hunter

## Goal

Audit the cryptographic posture of the target based on artifacts
captured by prior (active) skills — TLS banner/cipher data from
`web-recon-active`'s nmap output, cookies / tokens captured by
`session-flaw-hunter` or `jwt-hunter`, and key-shaped strings found by
`secrets-in-code-hunter`. This skill is passive by design (no outbound
probes beyond the occasional `WebFetch` of a known-safe path). It
implements WSTG-CRYP-01 through WSTG-CRYP-04 and maps findings to
CWE-327 (Use of Broken or Risky Cryptographic Algorithm), CWE-319
(Cleartext Transmission of Sensitive Information), CWE-326
(Inadequate Encryption Strength), and CWE-347 (Improper Verification
of Cryptographic Signature). The goal is to produce the consolidated
crypto-posture view that informs TLS hardening, cipher deprecation,
and library upgrade plans.

## When to Use

- After `web-recon-active` has captured TLS version / cipher data
  (from `nmap -sV` or `openssl s_client` output).
- After `session-flaw-hunter` / `jwt-hunter` / `api-recon` have
  captured cookie values and tokens.
- After `secrets-in-code-hunter` has surfaced key-shaped strings.
- When the orchestrator runs a "consolidated crypto review" phase
  before finalizing findings.

## When NOT to Use

- For active TLS enumeration — that lives in `web-recon-active`
  (nmap) or the operator runs `sslyze` / `testssl.sh` separately.
  This skill consumes the output, not produces it.
- For JWT-specific alg-confusion, `none`, or HS256 secret cracking
  — use `jwt-hunter` for the active probing; this skill only
  flags JWT artifacts with risky `alg` values seen in captures.
- For padding-oracle active exploitation — this skill flags
  CBC-mode token candidates for `jwt-hunter` / operator to
  manually probe; no active payload sending here.
- For code-level crypto review (weak PRNG use, hash-before-HMAC
  ordering) — that's `/security` static audit territory.
- Any asset not listed in `.claude/security-scope.yaml`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or
   doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND its
   `testing_level` is at least `passive`. This skill only reads
   locally-captured artifacts plus occasional WebFetch for one-shot
   header checks — no active probing.
3. Artifact inputs must come from prior in-scope skill runs. Do NOT
   analyze captures from assets outside the scope — check each
   artifact's provenance before including in the review.
4. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with
   status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{tls_scan_outputs}`: path to prior nmap / openssl TLS scan
  output (typically in `recon/nmap-{target}.*`)
- `{cookie_captures}`: path to session-flaw-hunter's cookie
  inventory (typically `session-tokens.md`)
- `{jwt_captures}`: path to jwt-hunter's token captures
  (typically `jwt-targets.md`)
- `{secret_captures}`: path to secrets-in-code-hunter's hits
  (hashes only; no plaintext)

## Methodology

### Phase 1: Transport-Layer Posture

1. **Parse captured TLS scan output** [WSTG v4.2, WSTG-CRYP-01]

   Do: Read `{tls_scan_outputs}`. Extract:
   - Supported TLS protocol versions
   - Supported cipher suites
   - Server certificate details (signature algorithm, key size,
     validity, SAN)

   Flag:
   - TLS < 1.2 supported (TLS 1.0, TLS 1.1, SSL 3, SSL 2)
   - RC4, 3DES, DES, MD5-signed ciphers
   - Anonymous ciphers (`aNULL`, `ADH`)
   - EXPORT ciphers
   - Certificate signed with SHA-1 or MD5
   - RSA key < 2048 bits
   - EC key < 256 bits

   Not-vulnerable condition: TLS 1.2+ with AEAD ciphers (AES-GCM,
   ChaCha20-Poly1305), forward-secrecy key exchange (ECDHE),
   RSA-4096 or EC-P-256+ keys.

   Record: Per-finding entries — each weak protocol/cipher as its
   own FINDING-NNN.

2. **HSTS + cookie-Secure cross-check**
   [WSTG v4.2, 4.2.7]

   Do: WebFetch `https://{target}/` once and check response headers
   for `Strict-Transport-Security`. Cross-reference
   `{cookie_captures}` for any sensitive cookie missing `Secure`.

   Vulnerable condition: HSTS absent (browsers can fall back to
   HTTP) AND sensitive cookies lack `Secure`.

   Record: Per-mismatch FINDING-NNN. Severity depends on whether
   the app is HTTPS-only-served (protected by TLS redirect) or
   also listens on HTTP.

### Phase 2: Sensitive-Data Transmission

3. **HTTP vs HTTPS of captured endpoints**
   [WSTG v4.2, WSTG-CRYP-03]

   Do: From `API_INVENTORY.md` and `ATTACK_SURFACE.md`, identify any
   endpoint that:
   - Serves a login form over HTTP
   - Accepts credentials over HTTP (even if the form's `action` is
     HTTPS — the form page itself being HTTP is a risk)
   - Accepts payment or PII over HTTP
   - Returns sensitive response bodies over HTTP

   Vulnerable condition: Any sensitive path is reachable via HTTP
   without redirect.

   Not-vulnerable condition: HTTP requests redirect 301/308 to
   HTTPS; HSTS with includeSubDomains enforces.

   Record: Per-endpoint FINDING-NNN.

### Phase 3: Token / Cookie Cryptographic Artifact Analysis

4. **Encoded-blob cipher-mode detection**
   [WSTG v4.2, 4.9.2]

   Do: For each captured session cookie that appears to be an
   encrypted blob (base64-decoded length is multiple of 8 or 16
   bytes), annotate:
   - Decoded length mod 16 == 0 → likely AES-CBC or AES-CTR
   - Decoded length mod 8 == 0 and not 16-aligned → likely 3DES
     or legacy
   - Fixed prefix patterns → may include IV (good) or may not
     (bad, static IV)

   Vulnerable condition: Fixed-length-aligned blob AND no
   authenticated-encryption indicator (no HMAC suffix — usually
   the last 32 or 64 bytes of the blob).

   Record: Each candidate for follow-up. Cross-reference
   `session-flaw-hunter` Phase 4 for the active bit-flip probe.

5. **JWT algorithm risk triage** [Bug Bounty Playbook V2, p. 154]

   Do: For each JWT captured, decode the header. Flag:
   - `"alg": "none"` being ACCEPTED (from jwt-hunter Phase 2)
   - `"alg": "HS256"` for a multi-service system (secret sharing
     risk)
   - Algorithm switch between issuances (RS256 on one endpoint,
     HS256 on another — confused-deputy risk)

   Record: Per-token-type FINDING-NNN. Cross-reference
   `jwt-hunter` for active confirmation.

### Phase 4: Key Material Leakage Review

6. **Scan secret-hit inventory for key shapes**
   [Bug Bounty Bootcamp, Ch 5, p. 63]

   Do: Read `{secret_captures}` — a list of hash-stored key-shaped
   strings found in public code. For each hit, categorize:
   - AES-256 key (32 bytes / 64 hex chars): typical shape
   - RSA private key (`BEGIN RSA PRIVATE KEY`): extreme severity
   - HMAC secret (high-entropy string > 32 chars): severity
     depends on scope
   - JWT signing secret (if matches a known library default):
     extreme severity

   Record: Per-hit FINDING-NNN with:
   - Hash reference (NEVER raw secret)
   - Discovery location (which skill found it, where)
   - Recommended action (rotate + audit key use)

7. **Default-secret pattern check**
   [WSTG v4.2, 4.9.3]

   Do: Cross-reference known framework-default secrets:
   - Flask: `"your-secret-key"`, `"your-256-bit-secret"`,
     `"change-me"`
   - Spring: `"default-spring-secret"`, `"changeit"` (keystore)
   - Laravel: `SOMERANDOMSTRING` (placeholder in `.env.example`)
   - Rails: `secret_key_base` with hex-like content
   - Node Express: `"your-secret"`, `"keyboard cat"`

   Vulnerable condition: Any captured secret matches a known
   default — confirm the app is actually using it (not just the
   string being in a template file).

   Record: Each match as High-severity finding even without
   exploitation confirmation.

### Phase 5: Error-Signal Oracle Review

8. **Padding-oracle candidate flagging**
   [WSTG v4.2, 4.9.2]

   Do: For each CBC-mode candidate from Phase 3, check whether
   `web-recon-active` or `session-flaw-hunter` captured
   differential error responses when the token was tampered with.

   Vulnerable signal: Different status codes / body sizes for:
   - Well-formed ciphertext (baseline)
   - Malformed ciphertext (decryption-invalid response)
   - Valid ciphertext with bad padding (padding-invalid response)

   Not-vulnerable signal: Identical generic error for all
   invalid-ciphertext variants.

   Record: Candidate flagged for follow-up active testing (NOT
   by this skill — delegate to `session-flaw-hunter` or operator).

### Phase 6: Consolidated Crypto Posture Report

9. **Aggregate cross-skill crypto findings**
   [Cross-skill aggregation]

   Do: Read `SECURITY_AUDIT.md`. For every crypto-related finding
   filed by other skills (JWT, session, CSRF-via-TLS, TLS
   enumeration), cross-reference into this skill's summary.

   Produce a one-page "Cryptographic Posture" section in
   `.claude/planning/{issue}/CRYPTO_POSTURE.md` with:
   - Transport layer status (TLS / HSTS / cookie-Secure)
   - Token crypto status (JWT alg, session cookie format)
   - Key material status (leaked, rotated, default)
   - Priority list of the top 3 crypto fixes

   Record: This is the hand-off document for the `harden` phase.

## Payload Library

No active payloads — this skill is analytical. Key probe patterns
inline in the methodology are:

- TLS weak-protocol/cipher grep patterns
- Base64-decoded length-modulus checks for cipher-mode inference
- JWT header alg-field triage
- Framework-default-secret signatures
- Differential-error pattern for padding-oracle candidates

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-327 (weak algorithm) for deprecated protocols/ciphers.
  CWE-319 (cleartext transmission) for HTTP-exposed sensitive data.
  CWE-326 (inadequate strength) for short keys. CWE-347 (improper
  signature verification) for alg-none / alg-confusion cases.
  CWE-798 for leaked keys.
- **OWASP**: WSTG-CRYP-01 through WSTG-CRYP-04. For APIs, API8:2023
  (Security Misconfiguration). For web apps, A02:2021 (Cryptographic
  Failures).
- **CVSS vectors**: TLS 1.0 supported with fallback —
  `AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N` (requires MITM). HTTP
  credential posting — `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`. Leaked
  active HS256 secret — `...C:H/I:H/A:H`. Weak-cipher-only TLS —
  `...AC:H/C:H/I:L/A:N`.
- **Evidence**: the TLS scan excerpt (for protocol/cipher findings);
  the captured cookie hex-decoded + length (for cipher-mode
  inference); the JWT decoded header (for alg risk); the
  secret-match hash ref + discovery skill.
- **Remediation framing**: platform / SRE engineer. Include:
  - TLS config snippets (nginx `ssl_protocols TLSv1.2 TLSv1.3;`,
    Apache `SSLProtocol`, ELB / CloudFront listener policy)
  - Cipher allowlist (Mozilla Intermediate or Modern list)
  - HSTS header configuration
  - Cookie-Secure / HttpOnly / SameSite defaults
  - Key rotation checklist (rotate, revoke old, audit use,
    monitor for ongoing use of old key post-rotation)

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
- `.claude/planning/{issue}/CRYPTO_POSTURE.md` — consolidated crypto
  view (unique to this skill)

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every finding cites the source skill and file for the
      artifact it analyzed (provenance chain)
- [ ] No active probes were sent (grep Skills Run Log for WebFetch
      calls; should be <5, all to scope-approved hosts)
- [ ] Leaked-secret findings reference hashes, never plaintext
- [ ] CBC-mode / padding-oracle candidates are flagged for follow-up
      but not actively probed by this skill
- [ ] CRYPTO_POSTURE.md summarizes the top 3 priority fixes in
      plain-English
- [ ] TLS findings consider the FULL protocol / cipher set, not
      just the "default" handshake behavior
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Generic 500 misread as padding oracle**: Many apps return
  HTTP 500 for any malformed ciphertext, regardless of whether
  padding was the issue. A single 500 signal isn't a padding-oracle
  indicator. The oracle requires THREE distinguishable response
  states: correct / garbled-but-padded / padding-error. If only
  two states exist, oracle exploitation is much harder or
  impossible.

- **Honeytoken secrets in public repos**: Some orgs commit fake
  credentials with alerting to detect scanners. Validating a
  "leaked" key (via a different skill) may trigger an internal
  incident. Coordinate with security team before validating
  suspicious public keys.

- **Permissive-but-unused-weak-crypto**: An app supports TLS 1.0 in
  the handshake capability set, but all current clients negotiate
  1.2+. The weak support is latent risk, not active vuln. File as
  Medium — the latent capability matters because protocol
  downgrade attacks exploit permissive support.

- **Double-encryption masking weak primitives**: An encrypted
  cookie actually wraps another encrypted cookie (base64 of base64
  of ciphertext). Length analysis misreads. Always decode fully
  before inferring cipher mode.

- **TLS scan staleness**: The `{tls_scan_outputs}` file may be
  days or weeks old. Cipher support changes with certificate
  renewal or config updates. Note the scan date; if > 7 days old
  or the asset had recent config changes, recommend re-scanning.

- **Client-side crypto confused with server-side**: JavaScript-
  performed AES decryption of client-stored data is almost always
  a pointless defense (the client has both the ciphertext and
  the key). File as Informational — not truly crypto failure,
  but worth calling out as weak design.

## References

External:
- WSTG-CRYP family: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/
- Mozilla TLS config generator: https://ssl-config.mozilla.org
- CWE-327: https://cwe.mitre.org/data/definitions/327.html
- CWE-319: https://cwe.mitre.org/data/definitions/319.html
- OWASP Cryptographic Storage Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia de Testes e Mitigação de Falhas Criptográficas.md`

Grounded in:
- The Web Application Hacker's Handbook, Ch 7 (Attacking Session
  Management) + Ch 18 (Attacking the Application Server)
- Bug Bounty Playbook V2 (JWT and Crypto sections)
- OWASP WSTG v4.2 (Section 4.9)
- Bug Bounty Bootcamp, Ch 5 (Recon of secrets)
- Tangled Web, Ch 4 (Content Encoding)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
