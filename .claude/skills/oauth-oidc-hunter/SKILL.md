---
name: oauth-oidc-hunter
description: "Tests OAuth 2.0 / OpenID Connect flows for redirect-URI validation weaknesses (exact match vs substring / subdomain confusion), open-redirect chaining, missing / predictable `state` (CSRF on account linking), authorization-code reuse, implicit-flow fallback, `response_type` tampering, and redirect-URI parameter pollution. Use when the target integrates 'Login with X' SSO, has OAuth-protected APIs, exposes `/.well-known/openid-configuration`, or uses bearer tokens. Produces findings with CWE-601 / CWE-352 / CWE-346 mapping, complete flow evidence (authorize → callback → token exchange), and PKCE / strict-match remediation. Defensive testing only, against assets listed in .claude/security-scope.yaml."
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
  source_methodology: "Guia de Vulnerabilidades em OAuth 2.0 e OpenID Connect.md"
  service_affecting: false
  composed_from: []
---

# OAuth / OIDC Hunter

## Goal

Test OAuth 2.0 and OpenID Connect integrations for the family of
flaws that let an attacker steal authorization codes / tokens,
perform account-linking CSRF, or bypass the intended authorization
flow. This skill implements WSTG-ATHN-10 (OAuth-specific portions)
and maps findings to CWE-601 (Open Redirect) for redirect-URI
issues, CWE-352 for missing state, CWE-346 (Origin Validation
Error) for cross-origin trust failures, and CWE-287 for auth
bypass. The goal is to give the platform / identity team a
concrete list of OAuth-layer flaws with complete flow evidence and
remediation (exact-match redirect allowlist, mandatory state,
single-use codes, PKCE, Authorization-Code-Flow-only policy).

## When to Use

- The target offers "Login with Google / GitHub / Microsoft / Okta"
  SSO, or integrates internal SSO via OAuth or OIDC.
- Login flows expose `client_id`, `redirect_uri`, `response_type`,
  `scope`, `state`, `code_challenge` parameters.
- The target is itself an Authorization Server issuing tokens to
  client applications.
- `/.well-known/openid-configuration` or `/oauth/jwks` endpoints are
  present (from `api-recon`).
- Bearer tokens (often JWTs) are issued via OAuth token endpoints.
- The orchestrator selects this skill after `auth-flaw-hunter`
  identifies an SSO-based login.

## When NOT to Use

- For the generic password-login flow (non-OAuth) — use
  `auth-flaw-hunter`.
- For JWT-specific cryptographic attacks on issued tokens — use
  `jwt-hunter` (this skill dispatches to it).
- For SAML-based SSO — not covered by source methodology; file a
  gap in `references/gaps.md`.
- For OAuth with custom non-standard flows (e.g., device-code,
  resource-owner-password) where this skill has no specific
  methodology — escalate to a human review.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or
   doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND its
   `testing_level` is `active`.
3. OAuth probes send real traffic to the target AS WELL AS to the
   identity provider (Google, Okta, etc.). The identity provider
   is almost always THIRD-PARTY and OUT OF SCOPE. Do NOT perform
   malicious probes against the IdP — only the target's OAuth
   CLIENT-side code is in scope. If testing the target as an
   Authorization Server (IdP side), confirm the scope file
   explicitly lists it as `asset_type: oauth_authorization_server`.
4. redirect_uri manipulation tests attempt redirects to an
   ATTACKER-CONTROLLED callback domain. This domain MUST be
   authorized in the scope file's `oob_listener` or
   `oauth_test_callback` list. Using arbitrary domains
   (webhook.site, etc.) without scope approval is forbidden.
5. If a redirect-URI bypass or code-theft bypass succeeds, STOP at
   the proof. Do NOT use the stolen token to impersonate real
   users beyond the test-account pair.
6. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with
   status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific OAuth endpoints
- `{user_a}`: test user A (for completing the happy-path flow
  baseline)
- `{oauth_callback_host}`: authorized callback-listener host from
  scope (e.g., `oauth-test.security.example.com`)

## Methodology

### Phase 1: Flow Discovery

1. **Locate OAuth endpoints** [Hacking APIs, Ch 2, p. 186]

   Do: Probe the target for:
   ```
   /.well-known/openid-configuration
   /oauth/authorize
   /oauth/token
   /auth
   /connect/authorize
   /connect/token
   /oauth2/v1/*
   ```
   Also parse `/.well-known/openid-configuration` JSON if present
   — it enumerates all relevant endpoints.

   Record: `.claude/planning/{issue}/oauth-endpoints.md` with
   (authorize_endpoint, token_endpoint, jwks_uri, grant_types,
   response_types, supported_scopes).

2. **Capture happy-path flow as baseline** [Bug Bounty Bootcamp, Ch 20]

   Do: Complete the full OAuth flow as `{user_a}` via the UI.
   Capture every request:
   - Initial authorize redirect (client → IdP)
   - IdP login + consent
   - IdP callback to `redirect_uri`
   - Client's token exchange at `/token`
   - Resulting session / access token

   Record: Baseline HAR in `oauth-flow-baseline.har`. Note the
   `client_id`, `state`, `code`, issued token structure.

### Phase 2: Redirect-URI Validation

3. **External-domain redirect probe**
   [Bug Bounty Bootcamp, Ch 20, p. 313]

   Do: Initiate the authorize request but replace `redirect_uri`:
   ```
   https://{target}/oauth/authorize?client_id={client_id}
     &redirect_uri=https://{oauth_callback_host}/captured
     &response_type=code&state=test
   ```

   Vulnerable response: The IdP accepts and redirects to
   `{oauth_callback_host}`, leaking the authorization code to the
   tester's callback listener.

   Not-vulnerable response: "Invalid redirect URI" error before
   login prompt.

   Record: Finding Critical if the callback-host leak succeeds.

4. **Subdomain / path confusion** [Bug Bounty Bootcamp, Ch 20]

   Do: Test partial-match bypasses:
   ```
   redirect_uri=https://{target}.{oauth_callback_host}/
   redirect_uri=https://{oauth_callback_host}/?q={target}
   redirect_uri=https://{target}@{oauth_callback_host}/
   redirect_uri=https://{target}%2F%40{oauth_callback_host}/
   redirect_uri=https://{oauth_callback_host}#{target}
   redirect_uri=https://{oauth_callback_host}%23{target}
   redirect_uri=https://{target}..{oauth_callback_host}/
   ```

   Vulnerable response: Any of these bypass the allowlist check.

   Record: Each successful bypass with the exact payload.

5. **Nested open-redirect chain**
   [zseano's methodology, p. 1000]

   Do: If the allowlist is strict but the target or its approved
   subdomains have any open-redirect vulnerability (discovered by
   `open-redirect-hunter`), chain:
   ```
   redirect_uri=https://{approved-subdomain-of-target}/logout?return=https://{oauth_callback_host}/
   ```

   Vulnerable response: Target redirects to the subdomain; the
   subdomain's open redirect forwards to the callback host, code
   leaks.

   Record: Chained-finding. Both skills should credit
   (open-redirect is the primary vuln; oauth is the leverage).

6. **Parameter pollution on redirect_uri** [WSTG v4.2, WSTG-INPV-04]

   Do: Submit multiple `redirect_uri` parameters:
   ```
   ?redirect_uri=https://{target}/callback
    &redirect_uri=https://{oauth_callback_host}/
   ```

   Test both orderings. Observe which value the server honors
   during the final redirect.

   Vulnerable response: Server honors the second (attacker-
   controlled) value.

### Phase 3: State / CSRF

7. **Missing state acceptance** [Hacking APIs, Ch 2, p. 186]

   Do: Initiate authorize without `state`:
   ```
   /oauth/authorize?client_id={client_id}
     &redirect_uri={target}/callback&response_type=code
   ```
   (no `state=...`)

   Complete the flow. Check if the target's callback accepts the
   code without validating state.

   Vulnerable response: Login completes — target doesn't require
   state. Enables account-linking CSRF (an attacker's pre-
   authorized code can be forced into a victim's session).

   Not-vulnerable response: Callback rejects "missing state".

8. **Predictable / constant state** [Hacking APIs, Ch 2, p. 186]

   Do: Capture the state used in the happy-path flow. Compare
   across 5 consecutive flows. Check:
   - Is state the same each time?
   - Does it encode session ID / timestamp predictably?
   - Can it be guessed from other information visible to an
     attacker?

   Vulnerable response: State is static, predictable, or not
   verified cryptographically.

### Phase 4: Authorization Code Reuse

9. **Code-replay probe** [Hacking APIs, Ch 2, p. 186]

   Do: Capture an authorization code. Immediately after the
   target's client exchanges it for a token, replay the same code
   to `/token`.

   Vulnerable response: Second exchange succeeds — the code wasn't
   invalidated on first use.

   Not-vulnerable response: Second exchange rejected with
   "invalid_grant".

   Record: Finding High — session-replay attacker with one captured
   code can generate additional tokens.

### Phase 5: Flow / Response-Type Downgrade

10. **`response_type` tampering**
    [WSTG v4.2, WSTG-ATHN-10]

    Do: Change `response_type` from `code` to `token`. Some servers
    accept this and fall back to the implicit flow, which leaks
    the access token directly in the redirect URL fragment.

    Vulnerable response: Server issues an access token in
    `#access_token=...` fragment.

    Not-vulnerable response: Server rejects with
    `unsupported_response_type`.

    Also test `response_type=code token` (hybrid) and
    `response_type=id_token token` if OIDC is in play.

### Phase 6: PKCE and Scope

11. **Missing PKCE for public clients**
    [OAuth 2.0 Security Best Current Practice]

    Do: For public clients (mobile apps, SPAs where the client
    secret is exposed), check whether the authorize request
    includes `code_challenge` and `code_challenge_method`. If
    absent, attempt to complete the flow without PKCE.

    Vulnerable response: Flow completes without PKCE — public
    client relies on client secret that's distributable.

    Record: Medium-to-High finding for public clients; Low for
    confidential clients.

12. **Scope creep / elevation probe**
    [OIDC-specific]

    Do: In the authorize request, append scopes that the
    documented client isn't authorized for:
    ```
    &scope=openid profile email admin manage-users
    ```

    Vulnerable response: IdP issues a token with elevated scopes.

    Not-vulnerable response: IdP rejects or silently drops
    unauthorized scopes.

## Payload Library

Categories:

- **External-domain redirect_uri**: direct attacker-host swap
- **Subdomain confusion**: `{target}.attacker`, `attacker?q=target`,
  fragment appending
- **URL-encoded confusion**: double-encoded slashes, `@`, `#`
- **Nested-redirect chains**: approved-subdomain open-redirect +
  attacker-host forward
- **Parameter pollution**: dual `redirect_uri`
- **Response-type tampering**: `code` → `token`, hybrid flows
- **State tampering**: missing, empty, static
- **Scope escalation**: unauthorized scopes appended

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-601 (Open Redirect) for redirect-URI bypass. CWE-352
  (CSRF) for missing state. CWE-287 (Improper Authentication) for
  code replay / flow bypass. CWE-346 (Origin Validation Error) for
  subdomain confusion. CWE-319 if tokens leak over HTTP.
- **OWASP**: WSTG-ATHN-10. For APIs, API2:2023 (Broken
  Authentication). A07:2021 (Identification and Authentication
  Failures).
- **CVSS vectors**: token leak via redirect-URI bypass —
  `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`. Account-linking CSRF —
  `...UI:R/C:H/I:H/A:N`. Code replay — `...AC:H/C:H/I:H/A:N`.
- **Evidence**: the authorize request with the malicious parameter,
  the callback log showing the leaked code or token, the
  subsequent `/token` exchange (if applicable), and the resulting
  session ownership.
- **Remediation framing**: identity / platform engineer. Include:
  - Exact-match redirect_uri allowlist (compare full URL,
    including query and fragment; reject on any deviation)
  - Mandatory unique `state` validation on callback
  - Single-use authorization codes (DB-level uniqueness +
    revocation on exchange)
  - PKCE enforcement for public clients
  - Disable implicit flow (`response_type=token`) at the
    authorization-server config
  - Scope allowlisting per client

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
- `.claude/planning/{issue}/jwt-targets.md` — appends any OIDC
  id_tokens for `jwt-hunter`

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every redirect-URI finding includes the callback log showing
      code leak + the exact bypass payload
- [ ] No probes were sent against the third-party IdP's login or
      consent pages (only against the client's authorize / callback
      endpoints)
- [ ] No real user's code / token was captured (only test-account
      probes)
- [ ] OIDC id_tokens were handed off to `jwt-targets.md`, not
      attacked in this skill
- [ ] Open-redirect chain findings cross-reference
      `open-redirect-hunter` if applicable
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Safe reflection of redirect_uri**: The `redirect_uri` value
  appears in the authorize-page HTML but isn't actually used for
  the callback — the real redirect target is server-side-configured.
  Reflection alone doesn't prove exploitability; confirm the
  callback actually lands at the attacker host.

- **IdP enforces the check, not the client**: Many modern IdPs
  (Google, Okta) enforce exact redirect-URI match. Apparent
  redirect-URI flaws may be blocked by the IdP even though the
  client is sloppy. Verify which party rejects the bypass —
  client-side flaws get filed; IdP-side rejections aren't findings
  against the target.

- **Secondary confirmation prompts**: The IdP shows "You are
  being redirected to {attacker-host}, continue?" before sending
  sensitive data. This is a defense in depth — exploitation
  requires additional social engineering. Lower severity.

- **Internal-only OAuth**: Findings in a `/dev/` or internal-only
  OAuth integration that has no prod data. Informational at best
  — note but don't emphasize.

- **Implicit-flow fragments don't reach the server**: A fragment-
  only token leak (`#access_token=...`) may not be reachable by
  server-side loggers at the attacker host — but it IS reachable
  by any JavaScript that runs there. Still a finding if the
  attacker host is attacker-controlled.

## References

External:
- WSTG-ATHN-10: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/10-Testing_for_Weaker_Authentication_in_Alternative_Channel
- OAuth 2.0 Security Best Current Practice:
  https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
- CWE-601: https://cwe.mitre.org/data/definitions/601.html
- PortSwigger OAuth labs:
  https://portswigger.net/web-security/oauth

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia de Vulnerabilidades em OAuth 2.0 e OpenID Connect.md`

Grounded in:
- Hacking APIs, Ch 2 (OAuth intro) + Ch 15 (case studies)
- Bug Bounty Bootcamp, Ch 20 (OAuth)
- OWASP WSTG v4.2 (WSTG-ATHN-10, WSTG-INPV-04)
- zseano's methodology (Open-redirect chaining)
- OWASP API Security Top 10 (API2:2023)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
