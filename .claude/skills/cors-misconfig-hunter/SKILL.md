---
name: cors-misconfig-hunter
description: "Audits CORS response headers for overly permissive policies — arbitrary-origin reflection with `Access-Control-Allow-Credentials: true`, subdomain confusion (`Origin: www.target.com.attacker.com` reflected), `null` origin acceptance, and permissive `Access-Control-Allow-Methods` exposing destructive verbs. Analyzes traffic already captured by `api-recon` and `web-recon-active` (passive) plus a small number of targeted Origin-header probes. Use when API responses include CORS headers; when cross-domain calls are visible in browser dev tools; or when the orchestrator needs an explicit CORS check. Produces findings with CWE-346 / CWE-942 mapping and strict-allowlist + no-credentials-with-wildcard remediation. Defensive testing only, against assets listed in .claude/security-scope.yaml."
model: sonnet
allowed-tools: Read, Grep, Glob, WebFetch(domain:*.in-scope-domain.com)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: client-side
  authorization_required: true
  tier: T2
  source_methodology: "Guia Técnico_ Vulnerabilidades e Mitigação de Misconfigurações CORS.md"
  service_affecting: false
  composed_from: []
---

# CORS Misconfig Hunter

## Goal

Audit CORS (Cross-Origin Resource Sharing) response headers for
misconfigurations that let a malicious origin read
authenticated API responses cross-domain — bypassing the Same-
Origin Policy's default protection. Flags overly-permissive
`Access-Control-Allow-Origin` reflection, dangerous
`Access-Control-Allow-Credentials: true` combined with wildcard
or reflected origins, `null` origin acceptance, permissive
`Access-Control-Allow-Methods` exposing destructive verbs, and
subdomain-confusion bypasses. This skill implements WSTG-CLIENT-07
and maps findings to CWE-346 (Origin Validation Error) and
CWE-942 (Permissive Cross-domain Policy with Untrusted Domains).
The goal is to hand the backend / infra team a concrete list of
CORS-layer flaws with strict-allowlist remediation.

## When to Use

- API responses include `Access-Control-Allow-Origin` headers
  (captured by `api-recon`).
- `Access-Control-Allow-Credentials: true` is observed in ANY
  authenticated response.
- Cross-domain calls appear in the application's normal traffic
  (indicating CORS is in active use).
- `Origin` request header is reflected in responses.
- The orchestrator selects this skill after `api-recon` flags
  CORS-relevant headers.

## When NOT to Use

- For CSRF specifically (cookie-based cross-site state change) —
  use `csrf-hunter`. The two share related surface but different
  mechanisms: CSRF exploits cookie auto-send; CORS misconfig
  exploits cross-domain read.
- For XSS (script execution in the target's own origin) — use
  `xss-hunter`.
- For same-origin issues like clickjacking — use
  `clickjacking-hunter`.
- For postMessage / cross-frame communication — use
  `dom-xss-hunter` (Phase 5).
- Any asset not listed in `.claude/security-scope.yaml`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist
   or doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND
   its `testing_level` is at least `passive`. This skill is
   passive — uses WebFetch with custom `Origin` headers, no
   state changes.
3. Probe traffic uses the authorized callback host from the
   scope as the `Origin` value. Do NOT use arbitrary public
   domains.
4. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
   with status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific endpoints to focus on
- `{user_a}`: authenticated session (needed to check CORS on
  authenticated-only endpoints)
- `{oauth_callback_host}`: authorized attacker-simulated Origin
  host from scope

## Methodology

### Phase 1: Passive Header Audit

1. **Grep captured responses for CORS headers**
   [Bug Bounty Bootcamp, Ch 19, p. 303]

   Do: Read `.claude/planning/{issue}/api-responses/` (from
   `excessive-data-exposure-hunter` or `api-recon`). Grep:
   ```bash
   grep -rE "^Access-Control-(Allow-Origin|Allow-Credentials|Allow-Methods|Allow-Headers|Expose-Headers|Max-Age|Vary)" \
     .claude/planning/{issue}/api-responses/
   ```

   Record: `.claude/planning/{issue}/cors-inventory.md` with
   (endpoint, response headers).

2. **Identify high-risk baseline patterns**
   [WSTG v4.2, WSTG-CLIENT-07]

   Do: Flag endpoints with any of:
   - `Access-Control-Allow-Origin: *` AND response returns
     sensitive data
   - `Access-Control-Allow-Origin: *` AND
     `Access-Control-Allow-Credentials: true` (browser rejects
     this combo, but the server config is still broken)
   - Origin reflection (`Access-Control-Allow-Origin: {whatever
     the request sent}`)
   - `Access-Control-Allow-Methods` including `DELETE`,
     `PUT`, `PATCH` on authenticated endpoints

   Record: Risk matrix per endpoint.

### Phase 2: Origin-Reflection Probe

3. **Simple external Origin** [Bug Bounty Bootcamp, Ch 19, p. 303]

   Do: For each endpoint with a CORS header, send:
   ```
   GET {endpoint} HTTP/1.1
   Origin: https://{oauth_callback_host}
   Authorization: Bearer {user_a_token}    (if authenticated)
   ```

   Observe `Access-Control-Allow-Origin` in the response.

   Vulnerable signal:
   `Access-Control-Allow-Origin: https://{oauth_callback_host}`
   (exact reflection). Combined with `Allow-Credentials: true`,
   this allows cross-origin reads of authenticated content.

   Not-vulnerable signal: Fixed trusted origin, absent header, or
   request rejected.

   Record: Per-endpoint reflection behavior.

4. **Subdomain-confusion probe** [Bug Bounty Bootcamp, Ch 19, p. 303]

   Do: Test partial-match bypasses:
   ```
   Origin: https://www.target.com.{oauth_callback_host}
   Origin: https://{oauth_callback_host}.target.com   (subdomain style)
   Origin: https://target.com{oauth_callback_host}
   ```

   Some servers use `startsWith(origin, "https://target.com")`
   or `endsWith(origin, "target.com")` — both bypassable.

   Vulnerable signal: The malicious origin is reflected in
   `Access-Control-Allow-Origin`.

5. **`null` origin probe** [Bug Bounty Bootcamp, Ch 19, p. 303]

   Do: Send `Origin: null`:
   ```
   GET {endpoint} HTTP/1.1
   Origin: null
   ```

   Browsers send `Origin: null` from:
   - Sandboxed iframes
   - `file://` URLs
   - Data URIs
   - Redirects cross-origin

   Vulnerable signal: `Access-Control-Allow-Origin: null` is
   returned. Attackers can construct a sandboxed iframe (via
   attacker-controlled page) whose `Origin` is `null` and then
   read the target's authenticated API.

### Phase 3: Credentials-With-Permissive-Origin Combination

6. **Wildcard + credentials check** [WSTG v4.2, WSTG-CLIENT-07]

   Do: If any endpoint returns BOTH:
   - `Access-Control-Allow-Origin: *`
   - `Access-Control-Allow-Credentials: true`

   Note: browsers reject this combination at the client side.
   But the server's willingness to set both still indicates a
   config error — and some older browsers / non-browser clients
   may accept.

   Vulnerable signal: Server sets both (config bug).

   Record: Finding Medium for the config bug; doesn't enable
   browser exploitation directly.

7. **Reflected-origin + credentials** [Bug Bounty Bootcamp, Ch 19]

   Do: The actual high-impact pattern: for every endpoint that
   reflects `Origin` (from steps 3-5), also check if
   `Access-Control-Allow-Credentials: true` is set.

   Vulnerable signal: Reflected origin + credentials = the
   attacker can read authenticated responses cross-domain.

   Record: Finding High-Critical. This is the classic
   CORS-misconfig RCE-for-data scenario.

### Phase 4: Preflight / Method Audit

8. **OPTIONS preflight check** [OWASP API7:2019]

   Do: Send OPTIONS with:
   ```
   OPTIONS {endpoint} HTTP/1.1
   Origin: https://{oauth_callback_host}
   Access-Control-Request-Method: DELETE
   Access-Control-Request-Headers: content-type,authorization
   ```

   Observe the preflight response's
   `Access-Control-Allow-Methods` and `Access-Control-Allow-Headers`.

   Vulnerable signal: `DELETE` (or `PUT`, `PATCH`) allowed for
   an endpoint where that's not the intended public usage, OR
   arbitrary headers allowed (enables smuggling of auth / custom
   headers cross-origin).

   Record: Per-endpoint method/header allow-list.

### Phase 5: `Vary: Origin` Absence

9. **Cache-poisoning-risk check**
   [WSTG v4.2, WSTG-CLIENT-07]

   Do: For endpoints with Origin-reflecting CORS, check whether
   the response includes `Vary: Origin`.

   Vulnerable signal: `Vary: Origin` is MISSING and the response
   is cacheable (no `Cache-Control: private`). A CDN cache could
   serve an attacker-originated response to a legitimate user,
   leaking the attacker's origin. Cross-reference
   `cache-smuggling-hunter`.

   Record: Per-endpoint Vary-header status.

## Payload Library

Categories:

- **Origin probes**: simple external, subdomain-confusion (6
  variants), null
- **Preflight probes**: OPTIONS with `Access-Control-Request-*`
  headers
- **Subdomain-variant list**:
  `{target}.{callback}`, `{callback}.{target}`,
  `www.{target}.{callback}`, `{target}%23{callback}`,
  `{target}.{callback}%2F`
- **Cross-check matrix**: headers to expect when the config is
  correct vs broken

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-346 (Origin Validation Error). CWE-942 (Permissive
  Cross-domain Policy with Untrusted Domains). For cache-related
  issues, CWE-524.
- **OWASP**: WSTG-CLIENT-07. For APIs, API8:2023 (Security
  Misconfiguration). A05:2021 (Security Misconfiguration).
- **CVSS vectors**: reflected-origin + credentials on
  authenticated API —
  `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` (read-level compromise
  of any authenticated user's data). Subdomain-confusion —
  same. Wildcard-only (no creds) on public data — Informational
  to Low.
- **Evidence**: the request with the malicious `Origin` header,
  the response headers showing reflection and
  `Allow-Credentials: true`, and a short note on what sensitive
  data the endpoint returns.
- **Remediation framing**: backend / API gateway engineer.
  Include:
  - Strict allowlist of origins (exact match, not regex)
  - NEVER combine `Access-Control-Allow-Origin: *` with
    credentials-carrying endpoints
  - Don't accept `null` origin — reject explicitly
  - Minimize `Access-Control-Allow-Methods` to the minimum
    required (typically GET + POST)
  - Set `Vary: Origin` on any response with Origin-dependent
    CORS headers to prevent cache poisoning
  - For public APIs: document origin policy and publish the
    allowlist

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every finding shows the `Origin` request header and the
      `Access-Control-Allow-*` response headers side-by-side
- [ ] Reflected-origin findings always check
      `Access-Control-Allow-Credentials: true` — without
      credentials the severity is much lower
- [ ] `null` origin tests were run on all CORS-exposing
      endpoints
- [ ] Subdomain-confusion tests covered at least 4 variants
- [ ] Preflight findings include the specific dangerous methods
      allowed
- [ ] `Vary: Origin` absence is noted for cacheable endpoints
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Public/static reflection on non-sensitive data**: The
  endpoint reflects arbitrary origins but only returns public
  data (marketing pages, documentation). Not a vulnerability —
  note as Informational.

- **Credential-less reflection**: `Access-Control-Allow-Origin`
  reflects but `Allow-Credentials` is not set. Browsers won't
  attach cookies to the cross-origin request, so the attacker
  gets non-authenticated data only. Severity depends on what
  the endpoint returns without auth (often 401 → no risk).

- **Chrome / Firefox strict-enforce wildcard+credentials**:
  Modern browsers refuse to honor `AC-Allow-Origin: *` +
  `AC-Allow-Credentials: true`. The combo is inoperative in
  browsers — but may still enable exploitation via non-browser
  clients. File as config bug, severity Medium.

- **Legitimate cross-domain integration**: Some apps are
  designed for cross-origin use (CDN-serving, widget-embedding).
  Verify whether a permissive policy is intentional — and in
  that case, whether the endpoint actually returns sensitive
  data to begin with.

- **Defensive-chaos misleading patterns**: Security teams sometimes
  deploy CORS headers that look broken but are actually trap-
  signals. Confirm via behavior (can the probe actually read
  authenticated data?) not just header presence.

- **Subdomain takeover amplifies CORS**: If the CORS policy
  allowlists `*.target.com` AND a subdomain is takeoverable
  (cross-reference `subdomain-takeover-hunter`), the CORS
  allowlist is effectively permissive to any attacker. File as
  chained finding.

## References

External:
- WSTG-CLIENT-07: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing
- CWE-346: https://cwe.mitre.org/data/definitions/346.html
- CWE-942: https://cwe.mitre.org/data/definitions/942.html
- OWASP CORS Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing
- PortSwigger CORS:
  https://portswigger.net/web-security/cors

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia Técnico_ Vulnerabilidades e Mitigação de Misconfigurações CORS.md`

Grounded in:
- Bug Bounty Bootcamp, Ch 19 + Ch 21
- The Tangled Web, Ch 9 + Ch 16
- OWASP WSTG v4.2 (WSTG-CLIENT-07)
- OWASP API Security Top 10 (API7:2019, API8:2023)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
