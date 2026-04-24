---
name: mass-assignment-hunter
description: "Tests APIs for Mass Assignment (blind property injection, role escalation via `admin:true` / `isAdmin:1`, financial manipulation via `credit:9999`, `balance:N`), HTTP Parameter Pollution (duplicate query / body params), and method-swap-with-mass-assignment variants. Use when the target has REST APIs with object creation / update endpoints; when OpenAPI specs hint at properties not in the UI; or when `api-recon` surfaced hidden parameters via Arjun. Produces findings with CWE-915 / CWE-235 mapping, before/after object-state evidence, and DTO-based remediation. Defensive testing only, against assets listed in .claude/security-scope.yaml."
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
  tier: T1
  source_methodology: "Guia de Segurança_ HPP e Mass Assignment em APIs.md"
  service_affecting: false
  composed_from: []
---

# Mass Assignment Hunter

## Goal

Test API endpoints that accept request bodies for Mass Assignment —
the flaw where the framework binds client-supplied properties to
backend data models without an allowlist, letting an attacker inject
admin flags, role escalations, or financial-state fields that the UI
never exposes. Also covers HTTP Parameter Pollution (HPP) — duplicate
parameters that bypass validation. This skill implements WSTG-INPV-04
adjacencies and maps findings to CWE-915 (Improperly Controlled
Modification of Dynamically-Determined Object Attributes) and CWE-235
(Improper Handling of Extra Parameters). The goal is to hand the API
team a concrete list of unprotected write paths with before/after
object-state evidence and DTO / allowlist remediation.

## When to Use

- The target has REST or RPC APIs with POST / PUT / PATCH endpoints
  that create or update objects (users, products, orders, accounts,
  configurations).
- OpenAPI / Swagger specs list properties on response types that
  aren't in the client UI's forms (e.g., `isAdmin`, `verifiedAt`,
  `apiKey`).
- `api-recon` surfaced hidden parameters via Arjun that echo in
  create/update responses.
- The framework on the server side is known to bind raw JSON to
  models by default (Rails pre-strong-params, Spring without DTOs,
  Laravel Eloquent without `$fillable`/`$guarded`).
- The orchestrator selects this skill after `api-recon` maps the
  write endpoints.

## When NOT to Use

- For object-level authorization bypass (user accessing another
  user's object via ID) — use `idor-hunter` or `bola-bfla-hunter`.
- For function-level authz (non-admin calling admin-only endpoint) —
  use `bola-bfla-hunter` for BFLA specifically.
- For reading too much data in responses — use
  `excessive-data-exposure-hunter` (API3:2023 BOPLA counterpart).
- For injection flaws in individual parameter values (SQLi, XSS) —
  use the class-specific hunter.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or
   doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND its
   `testing_level` is `active`.
3. Mass-assignment testing triggers real write operations on real
   objects. Use ONLY controlled test objects (test accounts, test
   products) — NEVER probe production user records, production
   financial accounts, or admin objects of real people. If the only
   available resources are shared production data, halt and
   request a scoped test environment.
4. If a probe appears to have elevated the test account's privileges
   (e.g., `isAdmin: true` stuck), IMMEDIATELY file the finding and
   coordinate with the team to revert. Do NOT use the elevated
   account to exercise admin functions for "further exploration" —
   the elevation itself is the proof.
5. If the target is ambiguous, write it to
   `.claude/planning/{issue}/SCOPE_QUESTIONS.md` and halt for that
   target only.
6. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with
   status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific write endpoints to probe
- `{user_a}`: regular-user credentials for a test account
- `{user_admin}`: optional — admin credentials (to see what
  properties the admin UI actually sets, baseline)

## Methodology

### Phase 1: Map Writable Endpoints and Model Surface

1. **Inventory write endpoints** [Hacking APIs, Ch 11, p. 273]

   Do: From `API_INVENTORY.md`, extract every POST / PUT / PATCH
   endpoint. Focus on:
   - User creation / profile update
   - Account-tier changes
   - Order / transaction creation
   - Permission / role assignment
   - Configuration endpoints

   Record: `.claude/planning/{issue}/mass-assignment-targets.md`
   with (endpoint, method, documented fields from spec).

2. **GET object, inspect response for hidden properties**
   [Hacking APIs, Ch 11, p. 274]

   Do: For each write endpoint, GET the object it manages.
   Compare the response fields against what the UI's create/update
   form sends. Fields in the response but not in the UI's write
   request are candidates for blind-MA injection.

   Common high-value hidden fields:
   - `isAdmin`, `admin`, `is_admin`, `role`, `roles`,
     `permissions`, `is_superuser`
   - `verifiedAt`, `emailVerified`, `phoneVerified`, `kycStatus`
   - `balance`, `credit`, `wallet`, `accountLimit`
   - `createdBy`, `tenantId`, `organizationId`
   - `apiKey`, `secret`, `internalNotes`
   - `mfaEnabled`, `mfaRequired` — can DISABLE MFA via MA

   Record: Per-endpoint list of candidate injection fields.

### Phase 2: Blind Mass-Assignment Probing

3. **Admin-flag injection** [Hacking APIs, Ch 11, p. 276]

   Do: Trigger a standard profile-update request as `{user_a}`.
   Before sending, add these fields to the JSON body:
   ```json
   {
     "...existing fields...",
     "isAdmin": true,
     "is_admin": 1,
     "admin": true,
     "role": "admin",
     "roles": ["admin"]
   }
   ```

   Submit. Then GET the same object to check:
   - Did the extra fields persist in the stored record?
   - Does a protected /admin endpoint now return 200 for this
     session?

   Vulnerable response: The injected fields stuck AND access
   expanded.

   Not-vulnerable response: Fields silently dropped, or explicit
   400 error listing them as unknown.

   Record: FINDING-NNN Critical if access actually escalated.

4. **Verification-flag injection**
   [OWASP API Security Top 10, API6:2019]

   Do: Submit a profile-update with:
   ```json
   {
     "emailVerified": true,
     "phoneVerified": true,
     "kycStatus": "approved",
     "mfaEnabled": false
   }
   ```

   Vulnerable response: Stored and honored — a new account can
   skip verification / MFA.

   Record: Per-flag findings.

5. **Financial-state injection**
   [Hacking APIs, Ch 11, p. 272, 275]

   Do: Submit an update with financial fields:
   ```json
   {"credit": 9999, "balance": 100000, "creditLimit": 500000}
   ```

   Vulnerable response: Balance / credit updated without a real
   transaction.

   Record: FINDING-NNN Critical — direct monetary impact.

6. **Ownership re-assignment** [Hacking APIs, Ch 11]

   Do: Submit an update with cross-tenant fields:
   ```json
   {"organizationId": "{victim-org-id}", "tenantId": "...",
    "ownerId": "{admin-user-id}"}
   ```

   Vulnerable response: Object reassigned — can pivot into another
   tenant or impersonate ownership.

   Record: Severity High; cross-reference `idor-hunter` if the
   destination organization's data becomes accessible.

### Phase 3: HTTP Parameter Pollution

7. **Duplicate query parameters**
   [WSTG v4.2, WSTG-INPV-04]

   Do: For endpoints accepting query-string parameters, submit
   duplicates:
   ```
   ?user_id=attacker&user_id=victim
   ?amount=10&amount=100
   ?role=user&role=admin
   ```

   Observe which value is honored — first, last, or concatenated.

   Vulnerable response: Validation checks `user_id=attacker` (first
   occurrence) but the DB query uses `user_id=victim` (last) — or
   vice versa.

   Record: Per-endpoint parsing-order fingerprint.

8. **Duplicate body parameters** [WSTG v4.2, WSTG-INPV-04]

   Do: For form-encoded bodies, submit duplicates:
   ```
   role=user&role=admin
   ```

   For JSON bodies, test invalid-but-sometimes-accepted duplicate
   keys:
   ```json
   {"role": "user", "role": "admin"}
   ```

   Many JSON parsers silently use the last value; inconsistency
   between the validation parser and the storage parser creates a
   pollution path.

   Record: Findings where the validation parser sees one value and
   the storage layer sees another.

### Phase 4: Method-Swap Mass Assignment

9. **POST / PUT on GET endpoints** [Hacking APIs, Ch 11, p. 280]

   Do: For endpoints documented as `GET /resource/:id`, try
   `POST /resource/:id` or `PUT /resource/:id` with a body
   containing sensitive fields.

   Vulnerable response: 200 — and the body fields were applied
   (check via a subsequent GET).

   Not-vulnerable response: 405 Method Not Allowed.

   Record: Successful method-swap-with-MA findings; typically High.

10. **Method-swap + HPP combo** [Hacking APIs, Ch 11]

    Do: Combine methods: POST /resource with body containing
    `admin=true` AND query string `?admin=false`. The validator
    might check the query string but the binder uses the body.

    Record: Each combination's outcome.

### Phase 5: Verification via GET-Back

11. **Confirm state persistence**
    [Hacking APIs, Ch 11, p. 281]

    Do: For every seemingly-successful injection (200 status + no
    error in body), follow with a GET of the same object as
    `{user_a}` (or admin if needed to see the admin-only field).

    Vulnerable response: The injected field persists in the GET
    response.

    Not-vulnerable response: GET shows the original value — the
    injection was echoed but not stored (false positive in Phase 2).

    Record: Every "confirmed" finding must have a GET-back that
    shows the persisted change.

## Payload Library

Categories:

- **Admin-flag injection**: `isAdmin`, `admin`, `role`, `roles`,
  `permissions`, `is_superuser`, `owner`
- **Verification-flag injection**: `emailVerified`, `phoneVerified`,
  `kycStatus`, `mfaEnabled`, `mfaRequired`
- **Financial injection**: `balance`, `credit`, `creditLimit`,
  `wallet`, `points`
- **Ownership injection**: `organizationId`, `tenantId`, `ownerId`,
  `createdBy`
- **HPP variants**: duplicate params in query vs body vs JSON-key
- **Method-swap**: POST/PUT/PATCH on documented-GET endpoints

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-915 (Improperly Controlled Modification of
  Dynamically-Determined Object Attributes). For HPP, CWE-235
  (Improper Handling of Extra Parameters). For admin-flag cases
  specifically, also CWE-269 (Improper Privilege Management).
- **OWASP**: For APIs, API6:2023 (Unrestricted Access to Sensitive
  Business Flows) or API3:2023 (BOPLA) depending on impact.
  WSTG-INPV-04 for HPP.
- **CVSS vectors**: admin-flag injection —
  `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`. Balance manipulation —
  `...C:H/I:H/A:N`. Email-verification-skip — `...C:L/I:H/A:N`.
- **Evidence**: the injection request, the response, AND the
  subsequent GET-back proving persistence.
- **Remediation framing**: backend engineer. Include
  framework-specific snippets in `references/remediation.md`:
  - Laravel: `$fillable` / `$guarded` Eloquent attributes
  - Rails: Strong Parameters (`params.require(:user).permit(...)`)
  - Spring: `@JsonView` or explicit DTOs (not `@RequestBody User`)
  - Express: DTO-style validator libraries (Joi, zod,
    class-validator)
  - Django REST Framework: serializer `Meta.fields` allowlist
  - ASP.NET: `[Bind]` attribute allowlist

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every finding has a GET-back confirming persistence, not just
      a 200 status on the injection
- [ ] Privilege-escalation findings were filed and coordinated for
      revert — no admin account was used for exploration
- [ ] No production user's record was mutated (only test accounts
      and test tenants)
- [ ] HPP findings note the parser inconsistency (which layer saw
      which value)
- [ ] Remediation snippets match the server-side framework detected
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Echo-without-execution**: The response body reflects the
  injected field, but a subsequent GET shows it wasn't stored.
  Always confirm with GET-back; don't trust response echo.

- **Public-intended field misread**: `public_bio`, `public_display_name`,
  `tagline` look sensitive but are designed to be user-settable.
  Cross-reference documentation / UI before filing.

- **Silent field drop with 200**: The framework accepts the
  injection and returns 200, but internally stripped the extra
  fields before storing. This is actually the correct defense —
  don't file as a finding.

- **Idempotent-update false negative**: The second GET-back shows
  the same value as before the injection because nothing changed
  — BUT the injected field wasn't in the original object either.
  Distinguish by observing whether the field EXISTS in the GET
  response after the injection that didn't exist before.

- **Ownership-transfer with cleanup**: Some apps accept
  `organizationId` changes because they're legitimate for the
  admin-panel workflow; the check is at the CALLER level, not at
  the parameter level. If a regular user can use the endpoint
  without admin role, the caller-check is what fails — cross-
  reference `bola-bfla-hunter`.

- **MFA-disable through account update**: Flipping `mfaEnabled`
  through profile update is severe — attackers leverage it after a
  session hijack to prevent the legitimate user from regaining
  control. Always flag this specific pattern as Critical even if
  the finding "only" disables MFA.

## References

External:
- WSTG-INPV-04: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution
- CWE-915: https://cwe.mitre.org/data/definitions/915.html
- OWASP API6:2023: https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/
- OWASP Mass Assignment Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia de Segurança_ HPP e Mass Assignment em APIs.md`

Grounded in:
- Hacking APIs, Ch 11 (Mass Assignment) + Appendix A
- OWASP WSTG v4.2 (WSTG-INPV-04)
- OWASP API Security Top 10 (API6:2019, API3:2023, API6:2023)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
