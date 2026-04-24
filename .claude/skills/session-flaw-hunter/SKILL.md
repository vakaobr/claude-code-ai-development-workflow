---
name: session-flaw-hunter
description: "Tests session management for predictable tokens, session fixation, missing cookie flags (Secure / HttpOnly / SameSite), failed server-side invalidation on logout, excessive timeouts, and structured-token tampering. Use when the target uses cookie-based or token-based sessions for authenticated access; when logins are in scope; or when the orchestrator's inventory surfaces Set-Cookie headers with security-looking names (PHPSESSID, JSESSIONID, token, sid). Produces findings with CWE-384 / CWE-613 mapping, statistical-entropy evidence, and cookie-attribute remediation. Defensive testing only, against assets listed in .claude/security-scope.yaml."
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
  source_methodology: "Guia de Segurança e Gerenciamento de Sessão em Aplicações Web.md"
  service_affecting: false
  composed_from: []
---

# Session Flaw Hunter

## Goal

Test the target application's session-management layer for
vulnerabilities that let an attacker masquerade as another user
without their credentials: predictable session tokens, session
fixation, missing cookie security attributes, failed logout
invalidation, excessive timeouts, and structured-token tampering.
This skill implements WSTG-SESS-01 through WSTG-SESS-07 and maps
findings to CWE-384 (Session Fixation), CWE-613 (Insufficient
Session Expiration), CWE-384, CWE-1004 (Sensitive Cookie without
HttpOnly), and CWE-614 (Sensitive Cookie without Secure). The
goal is to hand the backend team a concrete list of session flaws
with framework-specific remediation (Laravel, Django, Express,
Spring Session).

## When to Use

- The target uses cookie-based sessions for authenticated access,
  with cookies named `PHPSESSID`, `JSESSIONID`, `ASPSESSIONID`,
  `connect.sid`, `laravel_session`, `_session_id`, or custom
  patterns like `sid`, `token`, `session`.
- Logins are in scope and `{user_a}` credentials are available for
  authenticated testing.
- Cookies appear without `Secure` / `HttpOnly` / `SameSite` flags,
  as observed during `web-recon-active`.
- Structured or encoded-looking tokens (base64, hex) are issued by
  the server — potential tampering vector.
- The orchestrator selects this skill after detecting auth-cookie
  activity in `API_INVENTORY.md` under the "Auth" section.

## When NOT to Use

- For JWT-specific flaws (algorithm confusion, `none` alg,
  secret-cracking) — use `jwt-hunter` instead.
- For OAuth 2.0 / OIDC-specific issues — use `oauth-oidc-hunter`.
- For authentication flaws at the login-flow level (credential
  stuffing resistance, MFA bypass, password reset) — use
  `auth-flaw-hunter`.
- For auth-flow state-diagram mapping only — use `auth-flow-mapper`
  for that; this skill tests the live session layer.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist
   or doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND
   its `testing_level` is `active`.
3. This skill collects 500+ tokens in rapid succession for
   entropy analysis (Phase 2, step 3). Confirm the asset's
   `rate_limit_rps` allows this — default 10 rps means ~1 minute
   for 500 tokens. If the asset has `rate_limit_rps < 5`, halt
   and request scope approval to temporarily raise the limit for
   this test only.
4. Do NOT attempt to brute-force session tokens. Entropy testing
   collects issued tokens; it does not guess tokens.
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
   with status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific login/auth endpoints
- `{user_a}`: credentials for test user A
- `{user_b}`: credentials for test user B (different account,
  required for cross-session token-binding tests)

## Methodology

### Phase 1: Locate Session Tokens

1. **Identify session cookies / headers** [WAHH, Ch 7, p. 210]

   Do: Log in as `{user_a}`. Capture all `Set-Cookie` headers and
   any `Authorization` / `X-Auth-Token` response headers. Filter
   for names that look session-bound (exclude tracking cookies
   like `_ga`, `_fbp`).

   Record: Session-token inventory in
   `.claude/planning/{issue}/session-tokens.md` with
   (cookie_name, domain, path, value_format).

2. **Verify cookie security attributes**
   [WSTG v4.2, WSTG-SESS-02]

   Do: For each session cookie, check attributes:
   - `Secure` (only sent over HTTPS)
   - `HttpOnly` (not readable from JavaScript)
   - `SameSite=Strict|Lax` (not sent cross-site)
   - `Domain` and `Path` scoping (narrowest possible)
   - `Expires` / `Max-Age` (reasonable lifetime)

   Vulnerable response: `Secure` missing on HTTPS-only sites
   (session can be stolen via MITM on HTTP); `HttpOnly` missing
   (XSS → cookie theft); `SameSite=None` without a clear
   cross-site need; `Domain=.example.com` when only
   `app.example.com` needs it.

   Record: Cookie-attribute matrix per cookie, file findings for
   each missing/weak attribute.

### Phase 2: Token Entropy Analysis

3. **Collect token sample + statistical test**
   [WAHH, Ch 7, p. 219]

   Do: Programmatically request login + logout 500 times (or
   another token-issuance endpoint if one exists), capturing the
   issued token each time. Save to
   `.claude/planning/{issue}/session-tokens-sample.txt`.

   Run statistical analysis:
   ```bash
   # Basic analysis
   cat sample.txt | awk '{print length}' | sort -u    # token-length consistency
   cat sample.txt | head -c 1000 | ent                # Shannon entropy
   ```

   Better: decode the token (if base64/hex) and feed the raw
   bytes to `dieharder` or `ent` for randomness testing.

   Vulnerable response: Tokens show patterns (shared prefix,
   sequential bytes, low entropy per byte), or statistical tests
   flag them as non-random.

   Not-vulnerable response: Tokens pass entropy tests (entropy
   >= 7.5 bits/byte for a base64-encoded string).

   Record: Statistical output + FINDING-NNN if entropy fails.

### Phase 3: Session Fixation

4. **Pre-login → post-login token continuity test**
   [WAHH, Ch 7, p. 244]

   Do: Start a clean session. GET the login page — capture the
   session cookie issued before authentication. Then POST valid
   `{user_a}` credentials — compare the post-login session
   cookie.

   Vulnerable response: The session cookie is unchanged after
   login — fixation risk. An attacker who set the cookie could
   pre-determine the authenticated user's session.

   Not-vulnerable response: The login response issues a new
   session cookie; the old value is invalidated.

   Record: FINDING-NNN with request sequence showing cookie
   continuity.

### Phase 4: Token Structure Tampering

5. **Decode and identify structured components**
   [WAHH, Ch 7, p. 212]

   Do: Attempt to decode the token value:
   ```
   echo "{token}" | base64 -d
   echo "{token}" | xxd -r -p
   ```

   If the decoded content contains recognizable fields (user ID,
   role, timestamp), record the structure.

   Vulnerable response: Token contains a decodable user ID or
   role claim — tampering is feasible.

   Not-vulnerable response: Token is opaque, or decodes to
   high-entropy random bytes.

6. **Bit-flip / field-modification tampering**
   [WAHH, Ch 7, p. 223]

   Do: For structured tokens, systematically modify one byte at a
   time (Burp Intruder "Frobber" or manual curl loops) and check
   whether modified tokens are accepted.

   Test specific field changes if structure is known:
   - Change the encoded user ID to another known user's ID
   - Flip role bits (`user` → `admin`)
   - Extend expiration timestamp

   Vulnerable response: Modified token is accepted; response
   content reflects the tampered identity.

   Not-vulnerable response: Any modification causes rejection (the
   token is signed or HMAC'd).

   Record: Successful tampering as a Critical finding.

### Phase 5: Logout and Timeout Invalidation

7. **Logout server-side invalidation** [WAHH, Ch 7, p. 242]

   Do: Log in as `{user_a}`, capture the session cookie. Invoke
   the logout endpoint. Replay a protected-resource request with
   the pre-logout cookie.

   Vulnerable response: The server still accepts the token and
   returns protected content after logout — logout only cleared
   the client cookie, not the server session.

   Not-vulnerable response: The request is rejected / redirected
   to login (token invalidated server-side).

   Record: FINDING-NNN with the replay evidence.

8. **Idle-timeout behavior** [WSTG v4.2, WSTG-SESS-07]

   Do: Log in, wait the configured idle timeout (or 15-30 min
   test), then attempt to use the session.

   Vulnerable response: Session remains valid after excessive
   inactivity.

   Not-vulnerable response: Session expires after a reasonable
   idle window.

   Record: Observed timeout in `session-tokens.md`; file
   FINDING-NNN if timeout is excessive (>24h for high-value
   apps; >7d is generally too long).

### Phase 6: Cross-User Token Binding

9. **Token-to-session binding test**
   [WAHH, Ch 7, p. 212]

   Do: Log in as `{user_a}`, capture cookie A. Log in as
   `{user_b}` in a separate context, capture cookie B. Try to
   access `{user_a}`'s protected resources using cookie A's
   session but with modifications that inject user B context
   (if the app carries user hints in other headers or request
   bodies alongside the cookie).

   Vulnerable response: Server accepts mixed-signal requests
   (relies on the injected hint rather than just the cookie).

   Not-vulnerable response: Authorization is strictly derived
   from the cookie, and conflicting hints are ignored or
   rejected.

   Record: Per-pattern findings.

## Payload Library

Categories:

- **Entropy probes**: login loop scripts for token collection
- **Structure decoders**: base64 / hex / URL-decode pipelines
- **Tampering templates**: bit-flip with varying position;
  targeted field-rewrites (user ID, role, timestamp)
- **Fixation probe**: pre-auth GET → auth POST → cookie diff
- **Timeout probe**: login + wait + reuse sequence

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md`
per the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-384 (Session Fixation) for fixation findings.
  CWE-613 (Insufficient Session Expiration) for timeout /
  logout failures. CWE-1004 (Sensitive Cookie without HttpOnly),
  CWE-614 (Sensitive Cookie without Secure), CWE-1275 (Sensitive
  Cookie with Improper SameSite). CWE-330 (Use of Insufficiently
  Random Values) for entropy failures.
- **OWASP**: WSTG-SESS-01 through WSTG-SESS-07. For APIs,
  API2:2023 (Broken Authentication).
- **CVSS vectors**: entropy failure enabling prediction —
  `AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N`. Missing Secure on HTTPS
  — `...AC:H/PR:N/.../C:L/I:N/A:N` (requires network position).
  Failed logout invalidation — `...C:H/I:H/A:N` (someone who
  already had the cookie can still use it).
- **Evidence**: token-issuance request/response sequences; the
  entropy-test output; the cookie-attribute matrix; diff of
  pre-/post-login tokens for fixation.
- **Remediation framing**: backend engineer. Include
  framework-specific snippets: Laravel (`session.secure=true,
  session.http_only=true, session.same_site='lax'`), Django
  (`SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
  SESSION_COOKIE_SAMESITE='Lax'`), Express
  (`express-session { cookie: { secure: true, httpOnly: true,
  sameSite: 'lax' } }`), Spring (`server.servlet.session.cookie.
  secure=true`).

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Entropy test used at least 500 tokens and reports entropy
      bits/byte
- [ ] Fixation test shows pre-login AND post-login cookies
      side-by-side
- [ ] Logout invalidation test replays the exact protected path
      used for baseline
- [ ] Cookie-attribute findings include the raw `Set-Cookie`
      header for evidence
- [ ] Tampering tests used benign field changes (flip `viewer`
      to `editor`; NEVER `admin` if it grants destructive
      permissions without confirmation)
- [ ] The rate-limit budget was honored during the 500-token
      sample
- [ ] Skills Run Log row updated from `running` to `complete`
      or `halted:{reason}`

## Common Issues

- **Static tracking cookies misread as session**: `theme=dark`,
  `_ga`, `consent_id` don't change on login because they're
  tracking, not session. Confirm a cookie is session-bound by
  (a) its name pattern and (b) its presence in authenticated-only
  requests.

- **IP / user-agent session binding**: The app appears to have
  no fixation protection because the cookie is static across
  requests — but the server enforces session validity by
  comparing the request IP or user-agent to what was captured at
  login. Test by replaying the cookie from a different
  IP/user-agent; if rejected, fixation is mitigated server-side.

- **Network-load jitter in timing probes**: Session behavior
  measurements can be skewed by server load. Re-run inconclusive
  tests 3 times.

- **False positive from logout test — token still accepted
  because of CDN caching**: Some edge-cached endpoints return the
  last cached response without contacting origin. Confirm by
  hitting an endpoint known to be non-cached (e.g., a write
  endpoint or one with `Cache-Control: no-store`).

- **SameSite=None without Secure fails silently**: Modern
  browsers reject cookies with `SameSite=None` that don't also
  have `Secure`. The cookie never persists. Distinguish "not
  set" from "set but rejected by browser" — if the site is
  HTTPS-only and cookies are missing from cross-site contexts
  even without an intentional test, the app is already
  browser-protected.

## References

External:
- WSTG-SESS family: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/
- CWE-384: https://cwe.mitre.org/data/definitions/384.html
- CWE-613: https://cwe.mitre.org/data/definitions/613.html
- OWASP Session Management Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia de Segurança e Gerenciamento de Sessão em Aplicações Web.md`

Grounded in:
- The Web Application Hacker's Handbook, Ch 7 (Attacking Session Management)
- OWASP WSTG v4.2 (Section 4.6)
- OWASP API Security Top 10 (API2:2019, API2:2023)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
