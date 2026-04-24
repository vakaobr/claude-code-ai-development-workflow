---
name: jwt-hunter
description: "Tests JSON Web Tokens for `alg: none` acceptance, missing signature validation, HS256 secret cracking, RS256-to-HS256 algorithm confusion, claim tampering (role/uid escalation), post-logout / post-password-change token validity, and `kid` / `jku` / `x5u` injection. Use when the target uses JWTs for auth (strings starting with `ey` in Authorization headers, cookies, or bodies); when issued tokens contain cleartext roles or identifiers; or when tokens persist after logout. Produces findings with CWE-327 / CWE-347 / CWE-287 mapping, tampered-token PoCs, and library-configuration remediation. Defensive testing only, against assets listed in .claude/security-scope.yaml."
model: sonnet
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  WebFetch,
  Bash(curl:*), Bash(wget:*), Bash(httpx:*), Bash(ffuf:*),
  Bash(gobuster:*), Bash(nuclei:*), Bash(jq:*), Bash(arjun:*),
  Bash(gf:*), Bash(gau:*), Bash(waybackurls:*),
  Bash(nmap:--script=safe*), Bash(nmap:-sV), Bash(nmap:-Pn),
  Bash(dig:*), Bash(host:*), Bash(whois:*),
  Bash(openssl:s_client*), Bash(openssl:x509*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: authentication
  authorization_required: true
  tier: T1
  source_methodology: "Guia de Segurança e Testes em Vulnerabilidades JWT.md"
  service_affecting: false
  composed_from: []
---

# JWT Hunter

## Goal

Test JWT-based authentication for the family of flaws that let an
attacker forge or replay tokens: `alg: none` acceptance, missing /
weak signature validation, HS256 secret cracking, RS256-to-HS256
algorithm confusion, claim tampering, failed logout / post-
password-change invalidation, and header injection (`kid`, `jku`,
`x5u`). This skill implements WSTG-SESS-08 / WSTG-ATHN-09 and maps
findings to CWE-327 (weak crypto), CWE-347 (improper verification
of cryptographic signature), CWE-287 (improper authentication).
The goal is to give the team a concrete list of JWT-layer flaws
with tampered-token PoCs and library-configuration remediation
for the JWT libraries in use (`pyjwt`, `jsonwebtoken`, `nimbus`,
`jose-jwt`, `firebase/php-jwt`).

## When to Use

- The target uses JWTs for auth — strings starting with `ey` in
  `Authorization: Bearer` headers, cookies, URL params, or
  response bodies.
- Tokens have 3 parts separated by periods (`header.payload.signature`).
- `api-recon` identified JWTs in the "Auth" section of
  `API_INVENTORY.md`.
- Tokens appear to persist after logout or password change.
- Header `alg` claim is `HS256` / `RS256` / `ES256` (most common
  vulnerable configurations).

## When NOT to Use

- For opaque / non-JWT session tokens — use `session-flaw-hunter`.
- For OAuth 2.0 / OIDC flow-level issues (PKCE missing, redirect-
  URI validation, scope creep) — use `oauth-oidc-hunter`; this
  skill focuses on JWT cryptography and claim handling.
- For SAML-based auth — scope doesn't overlap.
- For encrypted JWT (JWE) — source methodology doesn't cover JWE;
  file a gap in `references/gaps.md`.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist
   or doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND
   its `testing_level` is `active`.
3. JWT secret-cracking (Phase 4, step 7) is compute-intensive
   but only on the tester's machine — no traffic to the target.
   The probes themselves (submitting forged tokens) are
   low-volume.
4. If a forged token grants admin privileges, STOP probing once
   confirmation is obtained. Do not use the forged admin token
   to explore admin-only endpoints — the initial auth-bypass
   proof is enough.
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
   with status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific JWT-protected endpoints
- `{user_a}`: credentials for test user A (issues a JWT to
  examine)
- `{user_b}`: credentials for test user B (for cross-user claim
  tampering tests)
- `{wordlist}`: optional — path to HS256 secret wordlist (default
  `jwt-common-secrets.txt`)

## Methodology

### Phase 1: Token Discovery and Decoding

1. **Capture token(s) issued to user A** [Hacking APIs, Ch 8, p. 230]

   Do: Log in as `{user_a}`. Capture all JWT-like strings in
   `Authorization` headers, cookies, and response bodies.

   Record: `.claude/planning/{issue}/jwt-targets.md` with
   (location, token value, issued-at timestamp).

2. **Decode header and payload** [Hacking APIs, Ch 8, p. 189]

   Do: Split the token by periods. Base64-decode part 1 (header)
   and part 2 (payload). Both are JSON.

   ```bash
   echo "{token}" | awk -F. '{print $1}' | base64 -d | jq .
   echo "{token}" | awk -F. '{print $2}' | base64 -d | jq .
   ```

   Vulnerable condition: Payload contains cleartext identifiers
   or role claims (`sub`, `uid`, `role`, `is_admin`, `permissions`).

   Not-vulnerable condition: Payload is opaque (nested encrypted
   content, only a random `jti` reference).

   Record: Decoded header (with `alg` value) and payload per token.

### Phase 2: `alg: none` and Signature-Stripping

3. **Submit token with empty signature**
   [Hacking APIs, Ch 8, p. 233]

   Do: Take the original token. Reassemble as
   `{header}.{payload}.` (note the trailing period, empty
   signature). Send as Authorization.

   Vulnerable response: Server accepts the token — signature
   validation is skipped when empty.

   Not-vulnerable response: 401 / 403 / "invalid signature" error.

   Record: FINDING-NNN Critical if bypass succeeds.

4. **Modify header to `alg: none`**
   [Bug Bounty Playbook V2, p. 154]

   Do: Decode the header, change `"alg": "HS256"` to
   `"alg": "none"` (try variants: `"None"`, `"NONE"`, `"nOnE"`),
   re-encode to base64url (no padding), reassemble the token
   with an empty signature.

   ```bash
   printf '{"alg":"none","typ":"JWT"}' | base64 -w 0 | tr '+/' '-_' | tr -d '='
   ```

   Vulnerable response: Token accepted without verification.

   Record: FINDING-NNN Critical.

### Phase 3: Claim Tampering

5. **Toggle role / admin flag** [Hacking APIs, Ch 8, p. 189]

   Do: For payloads with role/admin claims, modify:
   - `"role": "user"` → `"role": "admin"`
   - `"is_admin": false` → `"is_admin": true`
   - `"permissions": ["read"]` → `"permissions": ["read","write","admin"]`
   - `"sub": "<user-a-id>"` → `"sub": "<user-b-id>"`

   Re-encode payload; keep original signature (now invalid).

   Vulnerable response: Server accepts the tampered claims —
   signature is not validated or was already bypassed in Phase 2.

   Not-vulnerable response: 401 / 403.

   Record: Cross-reference with Phase 2 findings (tampering
   typically requires a signature bypass to succeed).

6. **Swap user identity** [Hacking APIs, Ch 8]

   Do: With both `{user_a}` and `{user_b}` tokens, swap the
   payload `sub` / `uid` claim from user A's token to user B's
   ID. Submit in user A's session context.

   Vulnerable response: Server returns user B's data for user A's
   token — server trusted the claim without verifying the
   signature was generated for that specific claim.

   Record: FINDING-NNN, severity depends on whose data is
   disclosed.

### Phase 4: HS256 Secret Cracking (Compute-Offline)

7. **Attempt dictionary crack of HS256 secret**
   [Hacking APIs, Ch 8, p. 197]

   Do: Export the token to disk. Use `jwt_tool` or
   `hashcat -m 16500`:
   ```bash
   hashcat -m 16500 token.txt {wordlist}
   # Or with jwt_tool:
   jwt_tool {token} -C -d {wordlist}
   ```

   Default wordlist: common JWT secrets (`jwt-common-secrets.txt`
   — `secret`, `123456`, `your-256-bit-secret`, company-brand
   permutations).

   Vulnerable response: The wordlist cracks the secret within
   minutes. The tester can now sign arbitrary tokens.

   Not-vulnerable response: No match against common wordlists.
   (Absence of a crack doesn't prove strong secret — may still be
   weak against targeted attacks.)

   Record: If cracked, FINDING-NNN Critical with the discovered
   secret's first/last 4 chars only (hash the rest); demonstrate
   the ability to forge a new token but do NOT actually use it
   against the target beyond the single confirmation request.

### Phase 5: Algorithm Confusion (RS256 → HS256)

8. **Fetch server's public key** [Bug Bounty Playbook V2, p. 156]

   Do: Try common public-key-discovery endpoints:
   ```
   /.well-known/jwks.json
   /.well-known/openid-configuration  (has jwks_uri inside)
   /oauth/jwks
   /api/jwks
   ```

   Extract the RSA public key (either as JWK format or from a
   linked X.509 cert).

9. **Forge token with HS256 using public key as HMAC secret**
   [Bug Bounty Playbook V2, p. 156]

   Do: Take the token (originally RS256-signed). Modify header:
   ```json
   {"alg":"HS256","typ":"JWT"}
   ```
   Tamper payload as needed. HMAC-sign with the public key's raw
   bytes:
   ```bash
   openssl dgst -sha256 -hmac "$(cat public_key.pem)" \
     <<< "${header_b64}.${payload_b64}"
   ```

   Assemble and submit.

   Vulnerable response: Server verifies using the public key as an
   HMAC symmetric secret — forged token accepted.

   Not-vulnerable response: Server enforces strict algorithm
   matching.

   Record: FINDING-NNN Critical.

### Phase 6: `kid` / `jku` / `x5u` Header Injection

10. **`kid` path traversal** [Hacking APIs, Ch 8]

    Do: If the header has a `kid` (key ID) claim, the server
    likely uses it to look up a signing key. Attempt path
    traversal or SQL injection:
    - `"kid": "../../../../dev/null"` then sign with empty key
    - `"kid": "' UNION SELECT 'hardcoded-key'-- "` (if kid is
      DB-looked-up)
    - `"kid": "1; echo 'my-secret'-- "`

    Vulnerable response: Key lookup fails in a way that lets the
    tester choose the verifying key.

11. **`jku` / `x5u` attacker URL** [Hacking APIs, Ch 8]

    Do: Modify the header to add `"jku": "{oob_listener}/jwks.json"`
    where the OOB listener serves a JWKS with the tester's own
    public key. Sign with the corresponding private key.

    Vulnerable response: Server fetches the tester-controlled
    JWKS and verifies with the attacker's key.

    Not-vulnerable response: `jku` domain validated against
    allowlist, or `jku` header ignored.

    Record: Cross-reference `ssrf-hunter` — if `jku` fetches
    internal URLs, there's also an SSRF vector here.

### Phase 7: Lifecycle Invalidation

12. **Post-logout token acceptance** [Hacking APIs, Ch 8]

    Do: Log in as `{user_a}`, capture the token. Invoke the
    logout endpoint. Replay the pre-logout token against a
    protected endpoint.

    Vulnerable response: Token still accepted after logout —
    there's no server-side revocation (stateless JWT without
    denylist).

    Record: FINDING-NNN with severity based on how long tokens
    live; stateless JWTs without revocation are inherently
    higher-risk.

13. **Post-password-change token acceptance** [Hacking APIs, Ch 8]

    Do: Log in, change password, then replay the pre-change
    token.

    Vulnerable response: Token still works even though password
    changed — the app can't revoke active sessions after a
    potential compromise.

    Record: FINDING-NNN High — password-change failure to
    invalidate is a classic account-recovery weakness.

## Payload Library

Full per-category payloads in `references/payloads.md`:

- **`alg: none` variants**: `none`, `None`, `NONE`, `nOnE`
- **Signature-stripping**: empty third part with trailing period
- **Claim tampering templates**: role, admin-flag, sub, aud
- **HS256 secret wordlists**: common secrets, library-default
  secrets, brand-permutations
- **RS256→HS256 forge script**: openssl-based HMAC with
  public-key bytes
- **`kid` injection**: path traversal, SQLi, empty-value
- **`jku` / `x5u`**: attacker-controlled JWKS URL

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md`
per the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-347 (Improper Verification of Crypto Signature)
  for alg-none / signature-stripping / algorithm-confusion.
  CWE-327 (Use of Broken/Risky Crypto) for HS256 with weak
  secret. CWE-287 (Improper Authentication) for lifecycle
  invalidation failures. CWE-306 if algorithm-confusion lets
  unauth users forge admin tokens.
- **OWASP**: WSTG-ATHN-09 (JSON Web Tokens). For APIs, API2:2023
  (Broken Authentication).
- **CVSS vectors**: `alg: none` bypass —
  `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (essentially full
  auth bypass). RS256→HS256 — same. HS256 weak secret — same
  once cracked. Post-logout validity —
  `...AC:H/PR:N/.../C:H/I:H/A:N` (requires attacker to have
  intercepted a token previously).
- **Evidence**: the decoded original token (header + payload),
  the tampered/forged token, the request/response showing
  server acceptance, and (for HS256 cracks) the wordlist hit
  with redacted secret.
- **Remediation framing**: backend engineer. Include
  library-specific snippets:
  - `pyjwt`: `jwt.decode(token, key, algorithms=["RS256"])`
    (explicit algorithm allowlist)
  - `jsonwebtoken`: `jwt.verify(token, key, {algorithms:
    ["RS256"]})`
  - `nimbus` (Java): `JWSVerifier` with explicit algorithm
  - `firebase/php-jwt`: `JWT::decode($token, $keyObj)` where
    `$keyObj` specifies algorithm
  - Server-side token denylist for logout/password-change
    invalidation (Redis-based blacklist keyed on `jti` claim)
  - Minimum secret entropy: 256-bit (32-byte) random for HS256

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every forged-token finding includes the decoded original
      AND the forged variant side-by-side
- [ ] HS256 cracks redact the secret (first/last 4 chars + hash)
- [ ] No admin-scoped forged token was used beyond a single
      confirmation request (no admin-area exploration)
- [ ] Cross-user claim-swap tests used harmless queries, not
      state-changing mutations
- [ ] `jku` testing used the authorized OOB listener from the
      scope file
- [ ] Post-logout / post-password-change tests replayed against
      the same protected path that worked before the lifecycle
      event
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Universal 200 with error body**: The API returns HTTP 200
  for every request but the body contains
  `{"error":"Unauthorized"}`. Automated tools misread. Always
  inspect the body, not status.

- **Ignored claims**: The server accepts a modified payload
  (`is_admin: true`), but re-verifies permissions against a
  backend database using the `sub` claim — the tampering is
  inert. Distinguish by checking whether the SERVER's response
  changes (e.g., returns admin-only data) or not. If the
  claim-swap elicits no behavioral change, the tampering is
  accepted but not honored.

- **Secondary integrity check**: The app uses JWT but also
  requires a second signed artifact (e.g., an `X-App-Hmac`
  header derived from the request body + a separate secret).
  Algorithm-switch attacks on the JWT alone still fail because
  the second check rejects. Still a JWT finding, but severity
  is lower.

- **JWKS cache poisoning**: Some libraries cache the JWKS
  response for hours. A `jku` attack might fail the first try
  because the original JWKS is still cached — succeed on
  second try after cache expiry. Note the caching behavior.

- **Token-revocation UI without server-side backing**: The app
  shows a "log out of all sessions" button but the implementation
  only clears the client-side storage — server still accepts
  all previously-issued tokens. Confirm by capturing a token
  before the logout event and replaying afterwards.

- **Symmetric-vs-asymmetric confusion in multi-issuer systems**:
  A system using RS256 internally may also have legacy endpoints
  that issue HS256 tokens. Some validators accept either without
  caring, which creates confused-deputy holes. Check whether the
  same endpoint accepts both algorithms.

## References

- `references/payloads.md` — full JWT attack payload catalog
- `references/remediation.md` — per-library secure-config
  snippets and denylist patterns

External:
- WSTG-ATHN-09: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/11-Testing_JSON_Web_Tokens
- CWE-347: https://cwe.mitre.org/data/definitions/347.html
- PortSwigger JWT labs:
  https://portswigger.net/web-security/jwt
- jwt_tool: https://github.com/ticarpi/jwt_tool

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia de Segurança e Testes em Vulnerabilidades JWT.md`

Grounded in:
- Hacking APIs, Ch 8 (JWT Attacks)
- Bug Bounty Playbook V2 (JWT chapter)
- OWASP WSTG v4.2 (WSTG-ATHN-09)
- OWASP API Security Top 10 (API2:2019, API2:2023)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
