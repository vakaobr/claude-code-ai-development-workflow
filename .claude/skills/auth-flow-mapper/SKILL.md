---
name: auth-flow-mapper
description: "Passively maps every authentication flow in the target — primary login, MFA, password reset, account registration, alternative channels (mobile API, SSO), and token issuance points — without running active attack probes. Produces AUTH_FLOWS.md with state diagrams, endpoint inventory, token-issuance timing, multi-stage sequences, and alternative-channel deltas. Consumed by auth-flaw-hunter (for attack planning), jwt-hunter (for token handoff), oauth-oidc-hunter (for OAuth-specific flows), and session-flaw-hunter (for session-layer testing). Use as a foundational T4 skill before any authentication-class hunter. Passive profile — observation only."
model: sonnet
allowed-tools: Read, Grep, Glob, WebFetch(domain:*.in-scope-domain.com)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: authentication
  authorization_required: true
  tier: T4
  source_methodology: "Mapeamento e Auditoria de Fluxos de Autenticação.md"
  service_affecting: false
  composed_from: []
---

# Auth Flow Mapper

## Goal

Systematically identify and document every authentication
mechanism the target uses — primary login, MFA, password reset,
registration, alternative channels (mobile API, SSO), and token
issuance points. This skill is the foundational T4 recon for the
auth-class hunter skills: its output (`AUTH_FLOWS.md`) tells
`auth-flaw-hunter`, `jwt-hunter`, `oauth-oidc-hunter`, and
`session-flaw-hunter` exactly what surface to test. This skill is
PASSIVE — observation only, no attack probes. Implements
WSTG-ATHN mapping (the discovery portions) and maps findings —
when any — to CWE-200 for leaked auth mechanisms, CWE-287 for
obvious auth design errors visible from traffic alone.

## When to Use

- At the start of any authentication-focused assessment — before
  `auth-flaw-hunter` / `jwt-hunter` / `oauth-oidc-hunter` /
  `session-flaw-hunter` run.
- When the orchestrator's phase-0 plan includes auth hardening.
- When the assessment scope includes multiple auth channels (web +
  mobile + API) and policy-drift is a concern.
- After `web-recon-active` / `api-recon` capture initial traffic
  but before targeted auth attacks.

## When NOT to Use

- For active auth attacks (lockout, enumeration, bypass) — use
  `auth-flaw-hunter`.
- For JWT-specific cryptographic attacks — use `jwt-hunter`.
- For OAuth flow attacks — use `oauth-oidc-hunter`.
- For session-layer issues — use `session-flaw-hunter`.
- For targets without any authentication — not applicable.
- Any asset not listed in `.claude/security-scope.yaml`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist
   or doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND
   its `testing_level` is at least `passive`. This skill only
   observes legitimate authentication flows — it performs the
   SAME actions a real user would (login with test credentials,
   walk through password-reset flow, etc.) and captures the
   traffic.
3. Use ONLY test credentials (from the scope's credentials
   vault). NEVER capture real customer auth flows for analysis
   — only test-account flows.
4. If any probe observation reveals live customer credentials or
   tokens in transit (e.g., HTTP basic auth visible to a
   network observer), IMMEDIATELY note and escalate — do NOT
   continue observing. Cross-reference `crypto-flaw-hunter`
   for transport-layer issues.
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
   with status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific auth flows to focus on
- `{user_a}`: test-account credentials (primary)
- `{user_b}`: second test-account credentials (for
  comparison between accounts)

## Methodology

### Phase 1: Enumerate Auth-Related Endpoints

1. **Walk the application** [WAHH, Ch 21, p. 805]

   Do: Manually navigate (or script via an intercepting proxy)
   the target's authentication surface:
   - Primary login page
   - "Forgot password" / "Reset password" flow
   - "Register" / "Sign up" flow
   - MFA setup + challenge flows
   - "Change password" (authenticated context)
   - SSO "Login with X" buttons
   - Mobile deep-link auth if apps exist
   - "Remember me" flow
   - Logout

   Record: `.claude/planning/{issue}/auth-flow-raw/{flow}.har`
   (HAR-format capture per flow) and a human-readable endpoint
   inventory in
   `.claude/planning/{issue}/auth-flow-endpoints.md`.

2. **Identify hidden auth endpoints via spec/doc**
   [Hacking APIs, Ch 7, p. 156]

   Do: If an OpenAPI / Swagger spec exists (from
   `api-recon`), extract:
   - All `/auth/*`, `/login`, `/oauth/*`, `/sso/*` paths
   - All paths tagged `authentication` / `security` /
     `authorization`
   - Deprecated auth endpoints (may lack modern hardening)

   Cross-check spec-declared endpoints against what the UI
   actually uses — unused-but-reachable deprecated paths are
   candidates for `auth-flaw-hunter` Phase 5 (alternative-channel
   policy drift).

### Phase 2: Document Multi-Stage Flows

3. **Primary login sequence** [WAHH, Ch 6, p. 188]

   Do: Complete the primary login as `{user_a}`. Document each
   HTTP request in sequence:
   - Initial GET of login page (captures CSRF token, form
     action, hidden fields)
   - POST of credentials
   - Any intermediate redirects
   - MFA challenge (if enabled)
   - Final authenticated landing page

   For each request, note:
   - Method + path
   - Request body shape
   - Response status
   - Set-Cookie / Authorization / state headers issued
   - Redirect chain

   Record: Sequence diagram in
   `.claude/planning/{issue}/auth-flow-raw/primary-login.md`.

4. **MFA flow details** [Hacking APIs, Ch 3, p. 186]

   Do: If MFA is set up, capture:
   - How the MFA challenge is initiated (immediately after
     password? after a partial session is issued?)
   - What "state" the server maintains between password-success
     and MFA-success (cookie? JWT? session token?)
   - MFA code format (4-digit, 6-digit, alphanumeric, TOTP)
   - Retry limits visible in UI ("you have 3 attempts
     remaining")

   Record: MFA details — especially the transition-state
   mechanism that `auth-flaw-hunter` Phase 4 will probe for
   bypass.

5. **Password-reset flow** [WAHH, Ch 6, p. 186]

   Do: Initiate password reset for `{user_a}`. Walk through:
   - Request for email
   - Email-link format (what token encodes, expiration)
   - Landing page when link is clicked
   - New-password submission
   - Session behavior after reset (does it auto-login? invalidate
     old sessions?)

   Record: Flow + questions for `auth-flaw-hunter` (e.g., "does
   old JWT still work after reset?").

6. **Registration flow** [WAHH, Ch 6]

   Do: Register a fresh test account via the registration flow.
   Walk through:
   - Required fields
   - Verification steps (email confirmation? SMS?)
   - What happens BEFORE verification (can the account log in
     with limited access?)
   - Post-verification session

   Record: Registration state machine.

### Phase 3: Token Issuance Timing

7. **Map when tokens are issued** [Hacking APIs, Ch 8, p. 189]

   Do: Across all flows observed in Phase 2, identify every
   point the server issues a token (cookie, JWT, opaque
   session ID, OAuth access-token). For each:
   - What verification state is required before issuance?
   - What claims does the token carry?
   - What's its expiration?
   - Is it rotated at key lifecycle points (login, logout,
     password-change, role-change)?

   Vulnerable observability: Tokens issued BEFORE full MFA
   completion (`auth-flaw-hunter` Phase 4 turf).

   Record: Token-issuance matrix in
   `.claude/planning/{issue}/auth-flow-tokens.md`.

### Phase 4: Alternative Channels

8. **Mobile-API parity check** [WSTG v4.2, WSTG-ATHN-10]

   Do: If the scope includes mobile apps or mobile-specific API
   paths (e.g., `/m/login`, `/api/mobile/*`), walk the auth
   flow there too. Compare:
   - Same endpoints as web? Or distinct?
   - Same MFA flow? Or different (or absent)?
   - Same rate-limit / lockout? Or looser?
   - Same token format / lifetime?

   Record: Channel-parity matrix — any drift is a candidate for
   `auth-flaw-hunter` Phase 5.

9. **SSO / social-login flows** [Bug Bounty Bootcamp, Ch 20, p. 307]

   Do: If the target offers "Login with Google / GitHub / Apple"
   / SAML SSO, walk each:
   - OAuth authorize URL
   - Consent page
   - Callback URL and parameters
   - Local user-creation when a new SSO identity arrives

   Flag for `oauth-oidc-hunter` handoff.

10. **Remember-me / long-lived token flows**
    [WSTG v4.2, WSTG-ATHN-09]

    Do: If the target offers "Remember me" or "Stay logged in":
    - Token format (separate cookie? separate JWT?)
    - Lifetime
    - Revocation behavior (does logout invalidate? password
      change?)

    Long-lived tokens often have weaker scrutiny than primary
    session tokens — flag for `session-flaw-hunter`.

### Phase 5: Synthesis and Handoff

11. **Produce AUTH_FLOWS.md**
    [Deliverable]

    Do: Aggregate all captures into
    `.claude/planning/{issue}/AUTH_FLOWS.md` with sections:

    - **Endpoint Inventory** (per auth surface)
    - **Primary Login Flow** (sequence diagram + key artifacts)
    - **MFA Flow** (transition-state details)
    - **Password Reset Flow** (sequence + questions)
    - **Registration Flow** (state machine)
    - **Token Issuance Matrix** (where + why + lifetime)
    - **Alternative Channels** (parity matrix)
    - **SSO / OAuth Flows** (handoff to oauth-oidc-hunter)
    - **Remember-Me / Long-Lived** (handoff to session-flaw-hunter)
    - **Handoff Questions** (specific probes for auth-flaw-hunter,
      jwt-hunter, oauth-oidc-hunter, session-flaw-hunter)

12. **JWT Artifact Handoff** [Bug Bounty Playbook V2, p. 154]

    Do: If any flow issues JWTs, capture one exemplar of each
    type (primary auth, refresh, OAuth access, OIDC id_token)
    and add to `.claude/planning/{issue}/jwt-targets.md` for
    `jwt-hunter`.

## Payload Library

No payloads — this skill is observational. The "probes" are just
standard login / register / reset flows exercised with test
credentials, captured via proxy.

## Output Format

This skill produces the **AUTH_FLOWS.md dossier** as its primary
output. It does NOT directly file findings unless:

- Auth flows expose sensitive data unencrypted (cross-reference
  `crypto-flaw-hunter`)
- Auth flows have obvious design-level issues visible from
  observation alone (e.g., a `remember-me` cookie that NEVER
  expires)

For passive-observable findings filed directly:

- **CWE**: CWE-200 (Information Exposure) for leaked auth
  details. CWE-287 for obvious design errors.
- **OWASP**: WSTG-ATHN family; A07:2021 for design-level.
- **CVSS vectors**: Informational to Low for observations;
  severity depends on whether the observation is immediately
  exploitable.
- **Evidence**: the captured HAR + a human-readable flow
  diagram.

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
- `.claude/planning/{issue}/jwt-targets.md` — JWT artifact
  handoff
- `.claude/planning/{issue}/AUTH_FLOWS.md` — primary dossier

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every auth flow was walked end-to-end with test
      credentials
- [ ] Every HTTP request in each flow was captured to HAR
- [ ] Token-issuance points are fully mapped (when + why + what
      claims + what lifetime)
- [ ] Alternative-channel parity matrix covers every channel
      the scope lists
- [ ] JWT artifacts handed off to `jwt-targets.md`
- [ ] SSO flows flagged for `oauth-oidc-hunter`
- [ ] Remember-me / long-lived tokens flagged for
      `session-flaw-hunter`
- [ ] Handoff Questions section lists specific probes for each
      downstream hunter
- [ ] No real customer credentials were captured (grep HAR for
      non-test usernames — should be zero)
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Uniform 200 OK masking errors**: Walking the flow with
  wrong credentials may return 200 with "invalid credentials"
  in the body. Normal user behavior is wrong-cred → 401 / 400
  — if the target always returns 200, the mapping needs to
  account for body-based error detection.

- **Inert multi-stage URLs**: The URL says `/step2` but the
  server actually tracks state via a cookie; `step2` in the
  URL is cosmetic. Not a real sequencing flaw. Verify the
  state mechanism during mapping.

- **Test-credential flag-triggers**: Some apps tag test
  accounts with special flags that make them skip MFA or get
  different rate limits. The mapped flow may not reflect real
  user experience. If possible, use multiple test accounts
  with varied configurations to cross-check.

- **Debug reflection disguised as real redirect**: Apps
  sometimes reflect `redirect_uri` in debug output without
  actually using it — the mapped flow would look OAuth-like but
  isn't. Confirm by watching whether the browser actually
  follows the reflected URL.

- **Captured credentials in HAR**: HAR files capture
  Authorization / Cookie headers. Sanitize HAR before saving or
  store under restricted access — or strip credentials via a
  post-processing step.

- **Scope-adjacent SSO providers**: Observing an OAuth flow
  captures traffic to the third-party IdP (Google, Okta). That
  traffic goes to an OUT-OF-SCOPE provider. Don't process or
  analyze IdP-side probes — only client-side callback behavior
  is in scope.

## References

External:
- WSTG-ATHN family: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/
- OWASP Authentication Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Mapeamento e Auditoria de Fluxos de Autenticação.md`

Grounded in:
- The Web Application Hacker's Handbook, Ch 6 + Ch 21
- Hacking APIs, Ch 6 + Ch 7 + Ch 8
- OWASP WSTG v4.2 (Section 4.4)
- Bug Bounty Bootcamp, Ch 20

Conversion date: 2026-04-24
Conversion prompt version: 1.0
