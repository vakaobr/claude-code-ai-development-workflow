---
name: excessive-data-exposure-hunter
description: "Audits API response bodies and client-side code for sensitive fields returned to the client that shouldn't be exposed — hashed passwords, internal IDs, admin flags, PII beyond what the UI needs, stack traces in errors, hardcoded secrets in JavaScript bundles, and 'debug' parameters that reveal extra state. Covers OWASP API3:2019 / API3:2023 BOPLA (read-side). Use after `api-recon` captures full response shapes; when the UI renders only a subset of the JSON that's returned; or when error pages reveal technical detail. Produces findings with CWE-213 / CWE-200 mapping and server-side-filtering / schema-validation remediation. Defensive testing only, against assets listed in .claude/security-scope.yaml."
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
  subcategory: api
  authorization_required: true
  tier: T2
  source_methodology: "Guia Técnico de Exposição Excessiva de Dados em APIs.md"
  service_affecting: false
  composed_from: []
---

# Excessive Data Exposure Hunter

## Goal

Audit API responses and client-side code for fields the server
exposes that the client shouldn't see — hashed passwords, internal
IDs, admin flags, PII beyond what the UI actually renders, stack
traces / software versions in error bodies, and hardcoded secrets
in JavaScript bundles. This skill covers the READ side of
API3:2023 (Broken Object Property Level Authorization — BOPLA);
the WRITE side (Mass Assignment) is covered by
`mass-assignment-hunter`. Maps findings to CWE-213 (Exposure of
Sensitive Information Due to Incompatible Policies) and CWE-200
(Information Exposure). The goal is to hand the backend team a
concrete list of over-exposing endpoints with server-side-
filtering + schema-validation remediation.

## When to Use

- `api-recon` captured full API response shapes that include fields
  the UI doesn't render.
- Legacy APIs that serialize entire DB records via
  `to_json()` / `to_hash()` / `jsonEncode(model)`.
- APIs with fields like `hashedPassword`, `resetToken`, `mfaSecret`,
  `internalNotes` visible in responses.
- Error pages that return stack traces, SQL snippets, or full
  filesystem paths.
- JavaScript bundles (via `web-recon-active`) with hardcoded API
  keys or connection strings.
- The orchestrator selects this skill after API inventory is
  populated, typically as part of the OWASP API Top 10 sweep.

## When NOT to Use

- For WRITE-side property injection (Mass Assignment) — use
  `mass-assignment-hunter`. The two are sister skills for
  API3:2023 BOPLA.
- For cross-user object access (BOLA) — use `idor-hunter` or
  `bola-bfla-hunter`.
- For actively exploiting exposed secrets — this skill flags them;
  `aws-iam-hunter` / `secrets-in-code-hunter` validate and
  enumerate impact.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist
   or doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND
   its `testing_level` is `active`.
3. This skill mostly reads already-captured traffic. New probes
   use only authenticated-user GETs (read-only). No state
   changes. Low risk.
4. If this skill discovers live credentials (API keys, AWS keys,
   DB strings) in responses, IMMEDIATELY note them in the
   finding with HASH-only storage (no plaintext) and flag for
   rotation. Do NOT validate the credentials here — hand off to
   `aws-iam-hunter` / `secrets-in-code-hunter`.
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
   with status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific endpoints to focus on
- `{user_a}`: authenticated session to capture full response shapes
- `{user_admin}`: optional — admin session to compare what an
  admin sees vs a regular user (delta is sometimes a flag)

## Methodology

### Phase 1: Response-Body Audit

1. **Capture full responses for every endpoint**
   [OWASP API3:2019, p. 12]

   Do: Using `{user_a}` session, exercise each endpoint and
   capture the COMPLETE response body — not what the UI renders,
   what the server actually sends.

   Tools: browser DevTools Network tab, Burp Suite history,
   `curl -i` direct.

   Record: Response corpus in
   `.claude/planning/{issue}/api-responses/`.

2. **Diff UI render vs response body** [Hacking APIs, Ch 7, p. 172]

   Do: For each endpoint, list the fields visible in the UI.
   Then list all top-level fields in the JSON response. The
   difference is candidate over-exposure.

   Vulnerable candidates: fields in response not rendered in UI
   AND that look sensitive by name:
   - Credentials: `password`, `hashedPassword`, `passwordHash`,
     `secret`, `apiKey`, `token`, `resetToken`, `refreshToken`
   - PII: `ssn`, `socialSecurityNumber`, `dateOfBirth`, `phone`,
     `homeAddress`, `taxId`, `passportNumber`
   - MFA: `mfaSecret`, `totpSeed`, `backupCodes`
   - Internal state: `isAdmin`, `role`, `internalId`,
     `organizationInternalId`, `tenantSecret`, `webhookSecret`
   - Technical: `databaseHost`, `s3Bucket`, `redisUrl`, `internalUrl`

   Not-vulnerable: fields render differently but the server
   returns ONLY what's needed for authorized display (e.g., the
   user's own email when they view their own profile).

   Record: Per-endpoint over-exposure matrix.

### Phase 2: Field-Name Heuristic Grep

3. **Regex scan of all captured responses**
   [Bug Bounty Bootcamp, Ch 21]

   Do: Grep the response corpus for sensitive field-name
   patterns:
   ```bash
   grep -rnE '"(password|passwordHash|hashedPassword|secret|apiKey|apiSecret|token|resetToken|refreshToken|privateKey|mfaSecret|totp[A-Za-z]*|ssn|socialSecurityNumber|taxId|creditCard)"\s*:' \
     .claude/planning/{issue}/api-responses/
   ```

   Record: Per-hit finding candidate.

4. **PII-pattern grep**
   [OWASP API3:2019]

   Do: Grep for values matching PII patterns (regardless of
   field name):
   - SSN: `\d{3}-?\d{2}-?\d{4}`
   - Credit card: `\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}`
   - AWS keys: `AKIA[0-9A-Z]{16}`
   - Private RSA key: `BEGIN RSA PRIVATE KEY`
   - Bearer tokens: `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+`

   Vulnerable: Any match in a response to a regular-user request.

### Phase 3: Client-Side Code Review

5. **JavaScript bundle scan** [WSTG v4.2, 4.1.5]

   Do: For every JS bundle loaded by the app (captured in
   `web-recon-active`'s spider output):
   - Download the bundle
   - Beautify with `js-beautify`
   - Grep for:
     ```
     AKIA[0-9A-Z]{16}                       # AWS
     AIza[0-9A-Za-z_-]{35}                  # Google
     sk_live_[0-9A-Za-z]{24,}               # Stripe
     xox[baprs]-[0-9A-Za-z-]+               # Slack
     ghp_[0-9A-Za-z]{36}                    # GitHub
     api[_-]?key\s*[:=]\s*['"][^'"]{16,}   # generic
     secret\s*[:=]\s*['"][^'"]{16,}        # generic
     https?://[^:]+:[^@]+@                  # creds-in-URL
     ```

   Vulnerable: Any hit is a secrets-exposure finding.

   Record: Per-file + line + HASH-of-secret (not plaintext).

6. **HTML comments + hidden form fields**
   [WSTG v4.2, 4.1.5]

   Do: For every rendered HTML page, check `<!-- ... -->`
   comments and hidden form fields for:
   - Developer notes leaking logic ("TODO: remove admin check
     for user_id=42 after demo")
   - Internal IPs / hostnames
   - SQL snippets
   - "DEBUG" flags or internal URLs

### Phase 4: Error-Response Audit

7. **Trigger + inspect errors** [WAHH, Ch 15]

   Do: For each endpoint, send malformed input to trigger the
   error path:
   - Malformed JSON body (syntax error)
   - Missing required field
   - Wrong Content-Type
   - Oversized payload (cross-reference `rate-limit-hunter`)

   Capture the error response. Check for:
   - Stack trace (`at com.example.Foo.bar(Foo.java:42)`)
   - SQL snippets (`ORA-00933`, `You have an error in your SQL`)
   - File paths (`/opt/app/config/db.yml`)
   - Software versions (`PHP 7.4.3`, `nginx/1.18.0`)
   - ORM errors revealing DB schema

   Vulnerable: Any of the above appear in error bodies.

   Not-vulnerable: Generic "An error occurred, please try again"
   response.

   Record: Per-error-path finding.

### Phase 5: Debug-Parameter Probing

8. **Debug-flag parameter fuzz**
   [Bug Bounty Bootcamp]

   Do: For each endpoint, append debug-suggesting parameters to
   the request:
   ```
   ?debug=true
   ?debug=1
   ?test=1
   ?verbose=true
   ?trace=true
   ?source=1
   ?dev=true
   ```

   Also test header variants:
   ```
   X-Debug: true
   X-Trace: true
   ```

   Vulnerable response: Any of these cause the response to
   include extra internal state, stack traces, or verbose
   logging data.

   Not-vulnerable response: The parameters are silently ignored.

   Record: Per-parameter finding.

### Phase 6: Admin-vs-User Diff

9. **Compare admin view to user view**
   [OWASP API3:2023 / BOPLA]

   Do: If `{user_admin}` is provided, call the same endpoint as
   admin and diff the response against `{user_a}`'s response for
   the same record.

   Vulnerable signal: Admin sees fields (internalNotes,
   mfaSecret, etc.) that a regular user shouldn't — and those
   fields are ALSO visible in the regular-user response but just
   null / empty. The field's mere PRESENCE in the regular-user
   response can leak schema info.

   Not-vulnerable: Admin response has admin-only fields; regular-
   user response omits those fields entirely.

   Record: Field-schema-leakage findings.

## Payload Library

No exploit payloads. Key probe patterns:

- **Field-name regex**: password / hashed / secret / apiKey /
  token / mfa / ssn patterns
- **PII-value regex**: SSN / CC / AWS / RSA / JWT patterns
- **Debug parameters**: `debug=true`, `verbose=true`, `trace=true`
- **Debug headers**: `X-Debug: true`
- **Error-trigger payloads**: malformed JSON, missing fields,
  oversized, wrong Content-Type

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-213 (Exposure of Sensitive Information Due to
  Incompatible Policies). CWE-200 (Information Exposure).
  CWE-209 for errors with sensitive-info leakage. CWE-798 for
  hardcoded secrets in JS bundles.
- **OWASP**: For APIs, API3:2023 (BOPLA — read side) + API3:2019
  (legacy Excessive Data Exposure). For web apps, A04:2021
  (Insecure Design). WSTG-INFO-05 for JS/HTML review.
- **CVSS vectors**: exposed admin-flag to regular user —
  `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`. Exposed password hashes
  — `...C:H/I:N/A:N`. Exposed live API keys — `...C:H/I:H/A:N`
  depending on key's scope. Exposed stack trace — `...C:L/I:N/A:N`.
- **Evidence**: the response body excerpt (with the sensitive
  field highlighted; if it's a secret, show only first/last 4
  chars + hash), the endpoint + user role, and a note on whether
  the UI actually uses the field.
- **Remediation framing**: backend engineer. Include:
  - Schema-based response serialization (e.g., Django REST
    Framework `Serializer` with explicit `fields`, Spring
    `@JsonView`, Node `class-transformer` with `@Expose`)
  - DTO-per-view pattern (separate `UserPublicDTO` vs
    `UserSelfDTO` vs `UserAdminDTO`)
  - Never `User.to_json()` / `user.*` auto-serialization
  - Structured error responses via a generic error handler
    (no stack traces in prod)
  - Disable debug endpoints / parameters in prod builds
  - JS-bundle secret scrubbing as a build step (and runtime
    check that `NODE_ENV=production` removes debug flags)

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
- `.claude/planning/{issue}/aws-iam-targets.md` — appends any
  discovered AWS keys for `aws-iam-hunter` validation
- `.claude/planning/{issue}/secrets-in-code-targets.md` — appends
  any bundle-leaked secrets for `secrets-in-code-hunter`

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every over-exposure finding shows the response body with
      the sensitive field AND the UI view confirming the field
      isn't needed
- [ ] Secret findings store hashes only (first 4 + last 4 +
      sha256 of the full value)
- [ ] Any live credentials were handed off for rotation BEFORE
      file is finalized
- [ ] Error-trigger tests used non-destructive malformed inputs
- [ ] Debug-parameter tests were exhaustive per endpoint (not
      just the first one)
- [ ] Admin-vs-user diff was run if `{user_admin}` was provided
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Field-name false positives**: `"token": "csrf-token-12345"` is
  a CSRF token needed by the UI, not a credential. Check the
  UI's consumption pattern.

- **Already-nullified fields**: Some APIs return `"password":
  null` or `"secret": ""`. The field's presence is still a
  schema leak but not an immediate credential exposure. Note
  severity as Medium rather than Critical.

- **Test-account data masks real risk**: If testing uses
  test accounts, PII fields may show test values (`test@example.com`,
  `555-0100`). The risk is that REAL users' data is similarly
  exposed. File the finding regardless; don't dismiss because
  test data was harmless.

- **Aggregation responses that are "too helpful"**: Dashboard
  endpoints often return rich data to populate charts /
  summaries. The UI renders aggregates but the response has
  per-record detail. Decide: if a regular user should be able to
  aggregate the underlying records (e.g., their own orders), it's
  fine; if the data is cross-user or admin-scope, it's a finding.

- **Stack traces in DEV environment**: Only a finding in
  production. Confirm the environment before filing.

- **Secrets that look sensitive but are public**: Some API keys
  are intentionally public (e.g., Stripe publishable keys, Google
  Maps frontend keys). Check whether the key is scoped to safe
  operations before filing.

## References

External:
- OWASP API3:2019 (Excessive Data Exposure):
  https://owasp.org/API-Security/editions/2019/en/0xa3-excessive-data-exposure/
- OWASP API3:2023 (BOPLA):
  https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- CWE-213: https://cwe.mitre.org/data/definitions/213.html
- WSTG-INFO-05: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia Técnico de Exposição Excessiva de Dados em APIs.md`

Grounded in:
- OWASP API Security Top 10 (API3:2019, API3:2023)
- Hacking APIs, Ch 7 (Endpoint Analysis)
- OWASP WSTG v4.2 (WSTG-INFO-05, WSTG-CRYP-03, WSTG-ERR-01)
- Bug Bounty Bootcamp, Ch 5 + Ch 21 (Recon + Hidden Resources)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
