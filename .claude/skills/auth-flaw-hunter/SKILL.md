---
name: auth-flaw-hunter
description: "Tests authentication subsystems for username enumeration, weak / absent lockout, multi-stage bypass (skipping MFA / security-questions stage), JWT signature integrity (dispatching to jwt-hunter), alternative-channel weakness (web vs mobile vs API), default-credential probing, and cleartext credential transmission. Use when login / password-reset / MFA flows are in scope; after `web-recon-active` maps the auth surface; or when the orchestrator's phase-0 plan prioritizes authentication hardening. Produces findings with CWE-287 / CWE-307 / CWE-522 mapping and layered auth hardening. Defensive testing only, against assets listed in .claude/security-scope.yaml — service_affecting: true."
model: opus
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
  source_methodology: "Guia de Testes e Mitigação de Falhas de Autenticação.md"
  service_affecting: true
  composed_from: []
---

# Authentication Flaw Hunter

## Goal

Test the target's authentication subsystem for flaws at the identity-
verification layer: username enumeration, weak or absent lockout,
multi-stage bypass (skipping MFA / security questions), JWT/SAML
signature issues (dispatch), alternative-channel weakness
(web vs mobile vs API policy drift), default-credential usage, and
cleartext credential transmission. This skill implements WSTG-ATHN-01
through WSTG-ATHN-10 and maps findings to CWE-287 (Improper
Authentication), CWE-307 (Excessive Authentication Attempts), and
CWE-522 (Insufficiently Protected Credentials). The goal is to hand
the team a concrete list of auth-layer flaws with generic-error,
lockout, and consistent-policy remediation.

## When to Use

- The target has login / password-reset / MFA-verify / signup /
  account-recovery flows in scope.
- `api-recon` surfaced multiple auth endpoints (web form + mobile
  API + SSO + "remember me") — policy-drift risk.
- Responses hint at enumeration (`"User not found"` vs `"Incorrect
  password"`).
- Multi-stage login / MFA appears in the inventory.
- The orchestrator selects this skill as part of a phase-0 auth-
  focused plan.

## When NOT to Use

- For session-layer flaws (post-auth cookie / token behavior) —
  use `session-flaw-hunter`.
- For JWT-specific cryptographic attacks — use `jwt-hunter`
  (this skill dispatches to it).
- For OAuth 2.0 / OIDC flow-level issues (PKCE missing, redirect-
  URI validation, scope creep) — use `oauth-oidc-hunter`.
- For rate-limit testing specifically on brute-force resistance —
  use `rate-limit-hunter` (this skill dispatches to it for the
  quantitative throughput tests; the qualitative lockout check
  stays here).
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or
   doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND its
   `testing_level` is `active`.
3. `service_affecting: true` — lockout testing generates real
   failed-login events in logs and may trigger real alerts to the
   security team. Confirm the asset's `service_affecting` is
   `approved`. Notify the security team BEFORE running Phase 2 so
   they can distinguish test traffic from real attack traffic.
4. Use ONLY a controlled test account (`{user_a}`) for lockout
   probing. NEVER trigger lockout on a real customer account, even
   in-scope. If the only available credentials are real-customer
   accounts, halt and request a dedicated test account.
5. Default-credential probes (Phase 6) use a limited wordlist of
   framework-default pairs; NEVER use leaked password dumps or
   credential-stuffing lists — that's `credential_stuffing` which
   is explicitly on the `never_run` technique list in the scope
   file.
6. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with
   status `running`. Include a note about the security-team
   notification.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific auth endpoints
- `{user_a}`: credentials for a controlled test account
- `{user_b}`: credentials for a second test account (needed for
  MFA-stage-skip tests where one path has MFA and the other
  doesn't)
- `{test_invalid_usernames}`: a small list of known-nonexistent
  usernames for enumeration probing (e.g., UUID-pattern strings)

## Methodology

### Phase 1: Credential Transport

1. **Verify HTTPS enforcement** [WSTG v4.2, WSTG-ATHN-01]

   Do: For each auth endpoint (login, reset, MFA), try fetching
   both `http://` and `https://` variants. Observe redirect
   behavior.

   Vulnerable response: Login form served over HTTP without
   redirect; credentials accepted over HTTP.

   Not-vulnerable response: HTTP redirects 301/308 to HTTPS before
   the form renders; HSTS header present.

   Record: Cross-reference `crypto-flaw-hunter` for TLS posture
   detail. File FINDING-NNN here for auth-specific mixing.

### Phase 2: Account Enumeration

2. **Response-body enumeration probe** [WSTG v4.2, WSTG-IDNT-04]

   Do: Submit login with:
   - Known-valid username + wrong password (from `{user_a}`)
   - Known-invalid username + wrong password (from
     `{test_invalid_usernames}`)

   Diff the two responses. Check:
   - Status code (same vs different)
   - Body text (exact match, or "User not found" vs "Wrong
     password")
   - Response time (timing side-channel)

   Vulnerable response: Distinguishable signals confirm user
   existence.

   Not-vulnerable response: Identical generic error for both.

   Record: Type of signal (body / status / timing) + sample
   responses.

3. **Forgot-password enumeration probe**
   [WAHH, Ch 6, p. 166]

   Do: Submit password-reset request for valid and invalid emails.

   Vulnerable response: "We sent an email to this address" for
   valid, "This email isn't registered" for invalid.

   Not-vulnerable response: "If this email is registered, we've
   sent a reset link" for both (identical).

   Record: FINDING-NNN. Severity typically Medium (Informational
   if enumeration is slow/rate-limited).

4. **Signup-flow enumeration**
   [WAHH, Ch 6, p. 166]

   Do: Attempt to register with valid and invalid emails.

   Vulnerable response: "This email is already registered" vs
   "Registered — check your inbox".

### Phase 3: Lockout Testing (Coordinated)

5. **Lockout threshold probe**
   [WSTG v4.2, WSTG-ATHN-03]

   Do: With `{user_a}` credentials and wrong password, submit up
   to 15 wrong-password attempts at ~1/sec. Stop at the FIRST
   defense signal (lockout / CAPTCHA / 429 / delay increase).

   Vulnerable response: All 15 attempts pass through with normal
   401 responses and no defense trigger.

   Not-vulnerable response: Defense kicks in after 3-5 failures.

   Record: Exact attempt number where defense triggered (or
   "none observed after 15").

   **Important**: After this test, restore `{user_a}` via the
   documented recovery flow or escalate to the asset owner to
   unlock. Never leave a locked account without a recovery path.

### Phase 4: Multi-Stage Bypass

6. **MFA-skip probe** [Bug Bounty Bootcamp, Ch 17, p. 276]

   Do: Complete stage 1 (password) as `{user_a}`. Capture the
   cookie / token / state the server issues to proceed to stage
   2 (MFA). Then, bypassing the MFA challenge, directly request
   a post-MFA endpoint (dashboard / API profile).

   Vulnerable response: The server returns authenticated content —
   authentication trusted the intermediate state without
   completing MFA.

   Not-vulnerable response: Redirect back to MFA challenge, or
   401.

   Also try:
   - Changing a `stage` parameter in a request body
   - Skipping security-question step after password
   - Direct POST to MFA-success endpoint with a forged
     `stage=complete` flag

7. **Stage-parameter tampering**
   [WAHH, Ch 6, p. 188]

   Do: If the auth flow uses a `stage` or `step` parameter in
   requests, try:
   - Skip ahead: `&stage=complete` or `&step=3`
   - Bypass verification: `&mfa_required=false`

   Record: Per-probe FINDING-NNN.

### Phase 5: Alternative-Channel Policy Drift

8. **Web vs Mobile vs API consistency check**
   [WSTG v4.2, WSTG-ATHN-10]

   Do: If the target has multiple auth channels:
   - Main web UI
   - Mobile API (often at `/api/mobile/` or separate subdomain)
   - Generic API (`/api/v1/auth/login`)
   - SSO / OAuth flow
   - "Remember me" / long-lived token endpoint

   Run Phase 2 (enumeration) and Phase 3 (lockout) against EACH.

   Vulnerable response: The mobile API has no lockout or reveals
   enumeration signals that the web form suppresses.

   Not-vulnerable response: All channels enforce identical policies.

   Record: Matrix of (channel, enumeration?, lockout attempts).

### Phase 6: Default Credentials

9. **Admin-panel default-cred probe**
   [Hacking APIs, Ch 8, p. 182]

   Do: If `/admin`, `/manage`, `/console`, or similar
   admin-looking paths are in the inventory, try a SMALL static
   set:
   - `admin:admin`
   - `admin:password`
   - `administrator:password`
   - `root:root`
   - `admin:{AppName}2020`, `admin:{AppName}2021`, etc.

   Limit to ~10 pairs total. NEVER use extended credential-stuffing
   lists.

   Vulnerable response: Successful auth with a default pair.

   Record: FINDING-NNN Critical. Severity requires no further
   demonstration — the default-cred admission alone is the
   finding.

### Phase 7: JWT / SAML Dispatch

10. **JWT artifact handoff** [Bug Bounty Playbook V2, p. 154]

    Do: If any auth flow issues JWTs (check headers / bodies for
    `ey`-prefixed strings), capture one token per user per channel
    and add to `jwt-targets.md`. Do NOT attempt cryptographic
    attacks here — delegate to `jwt-hunter`.

    Record: Token inventory; note any immediately-obvious red
    flags (`alg: none`, missing signature) for jwt-hunter's
    priority list.

## Payload Library

Categories:

- **Default credentials (limited)**: admin:admin, root:root, etc.
  (≤10 pairs — never credential-stuffing dump)
- **Invalid-username probes**: UUID-pattern usernames unlikely to
  exist (`nonexistent-user-a1b2c3d4`)
- **Stage parameters**: `stage=complete`, `step=final`,
  `mfa=skip`, `authenticated=true`
- **Multi-channel paths**: `/api/mobile/auth`, `/api/v1/login`,
  `/oauth/token`, `/remember-me`, `/refresh`

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-287 (Improper Authentication) for bypass. CWE-307
  (Excessive Authentication Attempts) for lockout failures. CWE-522
  (Insufficiently Protected Credentials) for cleartext transport.
  CWE-203 (Observable Discrepancy) for enumeration via timing /
  response diff.
- **OWASP**: WSTG-ATHN-01 through WSTG-ATHN-10. For APIs, API2:2023
  (Broken Authentication).
- **CVSS vectors**: MFA-skip —
  `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`. Default admin cred —
  `...PR:N/.../C:H/I:H/A:H`. Username enumeration alone —
  `...AC:L/C:L/I:N/A:N`. Cleartext creds on HTTP —
  `...AC:H/.../C:H/I:N/A:N` (requires MITM).
- **Evidence**: for enumeration, the diff between valid and invalid
  responses. For lockout, the attempt number and observed defense
  behavior. For bypass, the request that skipped the missing
  stage + the resulting authenticated response.
- **Remediation framing**: backend engineer + platform. Include:
  - Generic-error templates: "Invalid username or password" for
    all auth failures
  - Lockout config (framework-specific): Django
    `AXES_FAILURE_LIMIT`, Spring Security
    `PasswordPolicy`, etc.
  - Multi-channel policy parity checklist (audit all auth entry
    points share one lockout / error-template library)
  - Removing default admin accounts; rotating admin credentials;
    disabling admin panel from the public internet
  - Server-side stage-state tracking (not client-controlled)

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
- `.claude/planning/{issue}/jwt-targets.md` (appends discovered
  JWT tokens for jwt-hunter)

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every enumeration finding includes a diff (valid vs invalid
      response side-by-side)
- [ ] Every lockout finding includes the exact attempt count +
      observed response
- [ ] `{user_a}` was restored after lockout testing (or escalation
      noted)
- [ ] No credential-stuffing wordlist was used — only the limited
      default-cred list
- [ ] No real customer account's credentials were tested
- [ ] Multi-channel tests covered all alternative auth endpoints
      the recon surfaced
- [ ] JWT artifacts from auth flows were handed off to
      `jwt-targets.md`
- [ ] Security team was notified BEFORE lockout testing (unless
      scope permits silent runs)
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Uniform 200 with error body**: The server returns 200 for all
  login attempts but the body distinguishes valid/invalid. Always
  check the body text, not just status.

- **WAF interference misread as app defense**: An edge WAF blocks
  the IP after N requests. The app itself has no lockout. This
  still improves the posture but isn't an app-level defense —
  differentiate in findings (e.g., "lockout enforced at CDN/WAF;
  app-level defense absent").

- **Generic timing hits**: Response time increases during
  brute-force testing due to server load, not intentional slowdown.
  Re-run with low concurrency to distinguish genuine adaptive
  delay from incidental load.

- **Username enumeration only via rate**: Valid usernames are
  rate-limited differently from invalid ones (e.g., valid-user
  requests queue to a password-hash check; invalid-user returns
  immediately). Time the response at single-request cadence to
  confirm side-channel.

- **Lockout that unblocks too fast**: 60-second lockouts are
  essentially no defense against attackers with unlimited time.
  File as a finding ("insufficient lockout duration") — Medium.

- **MFA-skip that requires a stolen intermediate cookie**: The
  bypass requires an attacker-owned intermediate-state cookie,
  which is only obtainable post-password-validation. The
  impact is still account takeover of known-password accounts but
  lower for "anyone can skip MFA without any creds".

## References

- `references/remediation.md` — framework-specific lockout /
  error-template snippets

External:
- WSTG-ATHN family: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/
- CWE-287: https://cwe.mitre.org/data/definitions/287.html
- OWASP Authentication Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia de Testes e Mitigação de Falhas de Autenticação.md`

Grounded in:
- The Web Application Hacker's Handbook, Ch 6 (Attacking
  Authentication)
- Hacking APIs, Ch 8 (Auth Attacks)
- OWASP WSTG v4.2 (Section 4.4)
- OWASP API Security Top 10 (API2:2019, API2:2023)
- Bug Bounty Bootcamp, Ch 17 (Multi-stage bypasses)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
