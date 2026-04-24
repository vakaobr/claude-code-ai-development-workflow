---
name: csrf-hunter
description: "Tests state-changing endpoints for Cross-Site Request Forgery by auditing for anti-CSRF tokens, SameSite cookie protection, method-swapping bypasses, Referer/Origin header enforcement, and token-to-session binding. Use when authenticated endpoints modify state (password change, transfer, delete, permission changes) and the request is not obviously API-fetch-only; when session cookies lack SameSite protection; or when the orchestrator's inventory surfaces POST/PUT/PATCH/DELETE endpoints without visible tokens. Produces findings with CWE-352 mapping, auto-submit HTML PoCs, and token/cookie remediation. Defensive testing only, against assets listed in .claude/security-scope.yaml."
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
  subcategory: client-side
  authorization_required: true
  tier: T2
  source_methodology: "Guia de Segurança e Testes Contra Ataques CSRF.md"
  service_affecting: false
  composed_from: []
---

# CSRF Hunter

## Goal

Test the target's authenticated state-changing endpoints for
Cross-Site Request Forgery — the flaw that lets a third-party site
trigger actions in the victim's browser context by relying on
automatic cookie attachment. This skill implements WSTG-SESS-05 and
maps findings to CWE-352 (Cross-Site Request Forgery). The goal is
to hand the team a concrete list of unprotected state-changing
endpoints with auto-submit HTML PoCs and layered remediation
guidance (anti-CSRF tokens + SameSite cookies + custom headers +
interaction defenses).

## When to Use

- The target has authenticated endpoints that change state
  (password reset, email change, fund transfer, delete, permission
  grant, subscription).
- Session cookies are used for auth AND lack `SameSite=Strict` or
  `SameSite=Lax`.
- Endpoints accept GET with state-change side effects (classic
  GET-CSRF).
- API requests come without custom headers like `X-Requested-With`
  or `X-CSRF-Token` — indicating the server may be relying purely
  on cookies.
- The orchestrator selects this skill after `web-recon-active` or
  `api-recon` maps state-changing endpoints AND
  `session-flaw-hunter` confirms missing SameSite.

## When NOT to Use

- For UI-redress attacks that require a visible iframe — use
  `clickjacking-hunter`; CSRF is automatic-request, clickjacking
  is visible-click.
- For XSS-based CSRF-token-theft attacks — the primary flaw is the
  XSS; use `xss-hunter` or `dom-xss-hunter`.
- For state-changing GraphQL mutations — use `graphql-hunter`
  which has GraphQL-specific CSRF tests.
- For endpoints that require a secondary password re-entry or MFA
  — those inherently resist CSRF, skip.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist
   or doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND
   its `testing_level` is `active`.
3. CSRF testing requires triggering state-changing actions on
   `{user_a}`'s account. Use ONLY harmless actions — prefer
   changing a display preference, non-canonical notification
   setting, or a reversible profile field. NEVER test CSRF on
   destructive actions (account deletion, fund transfer, admin
   grant) without explicit pre-approval and an agreed rollback
   plan. Even if the scope file has `destructive_testing:
   approved`, this skill's default is non-destructive.
4. If the only state-changing actions available are destructive
   (e.g., the only thing the app does is "delete post"), halt
   and ask for approval before proceeding.
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
   with status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific state-changing endpoints
- `{user_a}`: credentials / session for test user A
- `{user_b}`: credentials / session for test user B (required for
  token-to-session binding tests)

## Methodology

### Phase 1: Inventory State-Changing Endpoints

1. **Extract state-changing endpoints from inventory**
   [Bug Bounty Bootcamp, Ch 9, p. 161]

   Do: Read `ATTACK_SURFACE.md` / `API_INVENTORY.md`. Extract
   every endpoint with method in `{POST, PUT, PATCH, DELETE}`
   AND that (a) requires auth AND (b) appears to modify
   server-side state (not just read-only query with POST body).

   Also extract GET endpoints whose names suggest state change
   (`/delete?id=`, `/unsubscribe?token=`, `/transfer?amount=`).

   Record: `.claude/planning/{issue}/csrf-targets.md` with
   (endpoint, method, baseline body, expected state change).

2. **Categorize by destructiveness**
   [Bug Bounty Bootcamp, Ch 9]

   Do: Tag each target as:
   - `safe_to_test`: changes a reversible non-critical field
     (display name, preference, notification toggle)
   - `dangerous_default`: destructive (delete, transfer, grant)
     — skip unless pre-approved
   - `needs_confirmation`: ambiguous; ask before testing

   Only `safe_to_test` proceeds to active probing. Stop and
   request confirmation for anything else.

### Phase 2: Token Presence Audit

3. **Audit for anti-CSRF tokens in request**
   [WSTG v4.2, WSTG-SESS-05]

   Do: For each safe target, log in as `{user_a}` and trigger
   the action normally (via the UI or the documented API call).
   Capture the request. Look for:
   - Hidden form fields with names containing `csrf`, `xsrf`,
     `token`, `_token`, `authenticity_token`, `anti_forgery_token`,
     `state`
   - Custom headers: `X-CSRF-Token`, `X-XSRF-TOKEN`,
     `X-Requested-With: XMLHttpRequest`
   - Double-submit cookies (same token value in cookie and body)

   Vulnerable response: No token present in the request, and no
   custom header that's non-browser-settable cross-origin, and
   cookie lacks `SameSite`.

   Not-vulnerable response: A cryptographically-random token is
   required, or a custom header is required.

   Record: Per-endpoint token-presence matrix.

### Phase 3: Removal and Tampering Tests

4. **Remove token entirely** [zseano's methodology, p. 1077]

   Do: For endpoints where a token is present, resubmit the
   request with the token parameter removed. Then resubmit with
   the token value set to empty string.

   Vulnerable response: The server processes the request
   successfully. The token presence is cosmetic.

   Not-vulnerable response: Server returns 403 / 400 / redirect
   to login.

   Record: FINDING-NNN for each endpoint that accepts missing
   tokens.

5. **Cross-session token binding**
   [Bug Bounty Bootcamp, Ch 9, p. 165]

   Do: Capture a valid token for `{user_a}`'s session. In a
   separate session authenticated as `{user_b}`, substitute
   user A's token in a state-changing request.

   Vulnerable response: The server accepts a token issued to a
   different session.

   Not-vulnerable response: Server rejects — token is strictly
   bound to the session that issued it.

   Record: FINDING-NNN — token is global, not session-bound.

6. **Method-swap bypass** [Bug Bounty Bootcamp, Ch 9, p. 164]

   Do: If the POST endpoint requires a token, try the same
   operation via GET (or other methods). Pass any required
   parameters as query string.

   Vulnerable response: GET is accepted without the token — CSRF
   defense was only applied to POST.

   Record: FINDING-NNN.

### Phase 4: Referer / Origin Enforcement

7. **Referer-less request** [Bug Bounty Bootcamp, Ch 9, p. 168]

   Do: Resubmit the request with the `Referer` header removed.
   Curl: `curl ... --referer ""`.

   Vulnerable response: The request is processed without a
   Referer — relying on Referer was weak because it can be
   stripped.

   Not-vulnerable response: Server requires Referer or Origin
   from a whitelisted origin.

8. **Forged Referer** [Bug Bounty Bootcamp, Ch 9, p. 168]

   Do: Send the request with Referer set to a visually-similar
   domain (`https://{target}.attacker.com/`) or a subdomain the
   app might loosely trust (`https://blog.{target}/` when the
   main app is `https://app.{target}/`).

   Vulnerable response: Loose matching accepts the forged
   Referer.

   Not-vulnerable response: Strict exact-match or wildcarded-only
   from intended origins.

### Phase 5: Confirmation via HTML PoC

9. **Auto-submit HTML PoC** [WAHH, Ch 13, p. 473]

   Do: For each confirmed vulnerable endpoint, build a
   self-submitting form HTML file in
   `.claude/planning/{issue}/csrf-poc/{endpoint-slug}.html`:

   ```html
   <!DOCTYPE html>
   <html><body>
   <form id="f" action="https://{target}/{path}" method="POST">
     <input name="{param1}" value="{val1}">
     <input name="{param2}" value="{val2}">
   </form>
   <script>document.getElementById('f').submit();</script>
   </body></html>
   ```

   Load the file in a browser that's separately authenticated to
   `{target}` as `{user_a}` and confirm the action fires.

   Vulnerable response: The action completes. Capture a
   screenshot or the post-action state change as evidence.

   Not-vulnerable response: Browser refuses the request, or the
   server rejects.

   Record: FINDING-NNN with the HTML PoC path attached.

10. **GET CSRF PoC** [WAHH, Ch 13]

    Do: For vulnerable GET endpoints, an `<img src>` embed is
    enough:

    ```html
    <img src="https://{target}/delete?id=42">
    ```

    Even simpler CSRF than form-POST — file the finding with
    this as evidence.

## Payload Library

Categories:

- **GET-CSRF probes**: `<img src>`, `<iframe src>`, link embeds
- **POST-CSRF auto-submit form**: hidden-field templates per
  content-type (form-urlencoded, multipart/form-data, JSON)
- **Referer manipulation**: empty-Referer, lookalike-domain
  Referer, subdomain Referer
- **Token-removal probes**: `&csrf_token=`, `&csrf_token=null`,
  token-removed body
- **Method-swap**: POST → GET, DELETE, PUT variants
- **Cross-session token**: user A token + user B cookie

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md`
per the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-352 (Cross-Site Request Forgery). For GET-CSRF
  with destructive effect, also CWE-650 (Trusting HTTP Permission
  Methods).
- **OWASP**: WSTG-SESS-05. For APIs, API8:2023 (Security
  Misconfiguration) because token absence is a config gap.
- **CVSS vectors**: account-takeover-class CSRF (password /
  email change) — `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`.
  Fund-transfer-class — `...C:H/I:H/A:N`. Notification-preference
  — `...C:N/I:L/A:N` (Low).
- **Evidence**: the HTML PoC file path, the state-change
  observed (screenshot or API check post-trigger), the request
  showing missing-or-removed token.
- **Remediation framing**: backend engineer. Include:
  - Framework snippets for token generation (Django
    `{% csrf_token %}`, Laravel `@csrf`, Express
    `csurf` middleware, Spring `CsrfToken`)
  - SameSite cookie configuration
  - Custom-header requirement for API calls
    (`X-Requested-With: XMLHttpRequest` with CORS
    preflight-forcing)
  - Double-submit cookie pattern for stateless backends

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every finding has an HTML PoC file AND a description of
      the resulting state change
- [ ] Every finding includes the request-with-token and
      request-without-token side by side
- [ ] No destructive-by-default action was tested without
      explicit approval
- [ ] Every vulnerable endpoint has a layered remediation
      (token + SameSite + custom header, not just one)
- [ ] Cross-session binding test was run if `{user_b}` was
      provided
- [ ] Skills Run Log row updated from `running` to `complete`
      or `halted:{reason}`

## Common Issues

- **Universal 200 with error body**: Server returns HTTP 200
  even for forged requests, but the response body contains
  `"error": "Invalid CSRF token"`. Automated tools misread the
  200 as success. Always check the response body, not just
  status.

- **Inert "token" parameter**: The app passes a parameter named
  `token` that's actually a tracking ID, campaign code, or
  deep-link attribution — not a security control. Removing it
  still fails authorization for unrelated reasons. Confirm a
  parameter is the CSRF token by checking if it's unique per
  session, rotates, and is validated server-side.

- **`SameSite=Strict` makes the app look vulnerable**: The app
  has no token, but cookies are `SameSite=Strict` so
  cross-origin requests never get them. Any HTML PoC fails
  because the browser doesn't send the cookie. The app is
  effectively protected by the cookie attribute — note as
  Informational rather than a vulnerability.

- **Multi-step confirmation**: The app requires a secondary
  step (password re-entry, MFA, CAPTCHA) before the
  state-change completes. CSRF alone can't complete the action.
  Filing as a vulnerability is noise unless the confirmation is
  also bypassable.

- **OPTIONS preflight masks the real request**: APIs with
  custom `Content-Type: application/json` trigger a CORS
  preflight; cross-origin `<form>` submissions can't set that
  header. The app is protected by CORS preflight, not an
  explicit token. Valid defense; note as such.

- **CDN-cached state-change endpoints**: Some apps serve state-
  changing endpoints through a CDN that caches responses. The
  response may indicate "success" from cache without the
  origin processing the forged request. Confirm by checking
  the actual post-trigger state.

## References

External:
- WSTG-SESS-05: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery
- CWE-352: https://cwe.mitre.org/data/definitions/352.html
- OWASP CSRF Prevention Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia de Segurança e Testes Contra Ataques CSRF.md`

Grounded in:
- Bug Bounty Bootcamp, Ch 9 (CSRF)
- The Web Application Hacker's Handbook, Ch 13 (Attacking Users)
- OWASP WSTG v4.2 (WSTG-SESS-05)
- zseano's methodology (CSRF testing)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
