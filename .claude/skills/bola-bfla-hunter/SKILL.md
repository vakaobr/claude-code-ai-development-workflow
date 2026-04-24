---
name: bola-bfla-hunter
description: "Tests APIs for Broken Object-Level Authorization (API1:2023 BOLA — cross-user resource access by ID manipulation) and Broken Function-Level Authorization (API5:2023 BFLA — non-admin users reaching admin-only endpoints via URL guessing or HTTP-method swap). Complements idor-hunter for web apps; this is the API-specific sister skill with API-class methodology and OWASP API Top 10 mapping. Use when `api-recon` surfaced resource-ID parameters and multi-role endpoints; when the orchestrator identifies administrative paths; or when two test accounts at different privilege levels are available. Produces findings with CWE-639 / CWE-285 mapping and authorization-middleware remediation. Defensive testing only, against assets listed in .claude/security-scope.yaml."
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
  subcategory: access-control
  authorization_required: true
  tier: T1
  source_methodology: "Guia Essencial de Segurança em APIs_ BOLA e BFLA.md"
  service_affecting: false
  composed_from: []
---

# BOLA / BFLA Hunter

## Goal

Test APIs for the top two OWASP API Security risks: Broken Object-
Level Authorization (API1:2023 — a user accesses another user's
resources via ID manipulation) and Broken Function-Level
Authorization (API5:2023 — a regular user reaches admin-only
functions via endpoint guessing or HTTP-method swap). This skill
implements WSTG-ATHZ-04 and WSTG-ATHZ-03 and maps findings to
CWE-639 (BOLA) and CWE-285 (Improper Authorization — BFLA). The
goal is to hand the API team a concrete list of
missing-authorization endpoints with paired test-account evidence
and centralized-middleware remediation.

## When to Use

- The target exposes REST / GraphQL / gRPC APIs with resource-ID
  path parameters (`/api/v1/users/{id}`, `/api/accounts/{id}`).
- `api-recon`'s inventory flagged administrative paths
  (`/api/admin/*`, `/api/internal/*`, `/api/manage/*`).
- Two test accounts at the same privilege level are available
  (for BOLA).
- A lower-privilege AND a higher-privilege test account are
  available (for BFLA).
- The orchestrator selects this skill after API recon identifies
  authorization-surface.

## When NOT to Use

- For web-app IDOR (non-API) — use `idor-hunter`. The two skills
  overlap; `idor-hunter` focuses on web-app endpoints with IDs in
  URLs/forms, while this skill is API-first with OWASP API Top 10
  framing.
- For mass-assignment-style privilege escalation via request
  body — use `mass-assignment-hunter`.
- For auth-bypass at the identity layer (no valid session at all)
  — use `auth-flaw-hunter`.
- For excessive-data-exposure (BOPLA, API3) — use
  `excessive-data-exposure-hunter`.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or
   doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND
   its `testing_level` is `active`.
3. BOLA/BFLA testing requires at least two test accounts; confirm
   both are approved (see `requires_auth_testing_credentials` and
   `test_credentials_vault_path`). NEVER test BOLA by attempting
   to access real customers' resources — only test-to-test
   accounts.
4. For BFLA tests against admin endpoints, if the regular-user
   token gets 200 on an admin endpoint, STOP at the first
   confirmation. Do NOT exercise admin functions (delete, grant,
   invite) beyond reading the response that confirms access.
   Coordinate revert with the platform team.
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with
   status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific endpoints to focus on
- `{user_a}`: regular-user test credentials
- `{user_b}`: second regular-user credentials (for A-B BOLA)
- `{user_admin}`: admin-user credentials (for BFLA — captures the
  admin request shape to compare / replay)

## Methodology

### Phase 1: Resource-ID Inventory

1. **Extract ID-bearing endpoints from API_INVENTORY**
   [Hacking APIs, Ch 10, p. 224]

   Do: From `API_INVENTORY.md`, filter endpoints where path / query
   / body / header contains resource identifiers:
   - Sequential integers: `/api/v1/user/123`
   - UUIDs: `/api/accounts/550e8400-e29b-41d4-...`
   - GUIDs in body: `{"account_id": 5001}`
   - Custom-header identities: `X-User-Id: 42`

   Record: `.claude/planning/{issue}/bola-bfla-targets.md` with
   (endpoint, method, ID location, baseline user-owned value).

2. **Identify admin-endpoint surface** [Hacking APIs, Ch 10, p. 227]

   Do: From the inventory, extract endpoints at paths that suggest
   admin scope:
   - `/api/admin/*`
   - `/api/internal/*`, `/api/manage/*`, `/api/ops/*`
   - `/api/v1/users` (list-all, vs `/api/v1/users/{id}`)
   - `/api/v1/invites`, `/api/v1/roles`, `/api/v1/permissions`
   - Anything with `all_`, `list_`, `manage_` prefixes

   Also discover undocumented admin endpoints via spec files (did
   `api-recon` extract a Swagger that listed admin-only paths?).

   Record: Admin-endpoint matrix.

### Phase 2: BOLA — Cross-User Object Access

3. **A-B token swap (horizontal BOLA)**
   [Hacking APIs, Ch 10, p. 225]

   Do: For each resource endpoint with user-A-owned IDs in the
   baseline, replay the request with user B's token but keeping A's
   resource ID.

   Vulnerable response: User B receives user A's data.

   Not-vulnerable response: 401 / 403 / 404.

   Record: FINDING-NNN per vulnerable endpoint. Evidence: user A's
   baseline AND user B's exploit request with A's ID.

4. **Array-wrapper bypass probe** [Hacking APIs, Ch 10, p. 230]

   Do: Some endpoints parse arrays differently from scalars. Test
   `{"account_id": [123]}` or `[123,456]` instead of
   `{"account_id": 123}`.

   Vulnerable response: Validation checks the first element but
   storage pulls from both; or array bypasses a type check that
   only validates scalars.

   Record: Per-endpoint findings.

5. **Side-channel ID enumeration**
   [Hacking APIs, Ch 10, p. 226]

   Do: For ID-protected endpoints, fuzz ID values:
   - `{valid-but-unauthorized-id}` → response
   - `{definitely-nonexistent-id}` → response

   Compare status codes, body sizes, timing. A distinguishable
   difference means existence can be enumerated even if access is
   denied.

   Vulnerable response: 403 for valid-not-yours vs 404 for
   nonexistent.

   Not-vulnerable response: Identical response (usually 404 or
   generic 403) for both.

   Record: Finding Medium — information disclosure via side
   channel.

### Phase 3: BFLA — Function-Level Access

6. **Admin-endpoint probe with regular-user token**
   [OWASP API Security Top 10, API5:2019]

   Do: For each admin endpoint, send a request with `{user_a}`'s
   token (regular privilege):
   ```
   GET /api/admin/users  Authorization: Bearer {user_a_token}
   GET /api/admin/settings  Authorization: Bearer {user_a_token}
   ```

   Vulnerable response: 200 — regular user reads admin data.

   Not-vulnerable response: 401 / 403.

   Record: Per-endpoint findings; Critical if admin data is
   sensitive.

7. **Method-swap BFLA probe** [Hacking APIs, Ch 10, p. 227]

   Do: For a resource endpoint where GET is documented, try other
   methods:
   ```
   DELETE /api/v1/users/123   — should require admin
   PUT /api/v1/users/123      — should require admin or self
   PATCH /api/v1/users/123/role
   ```

   Test with `{user_a}` (regular) token.

   Vulnerable response: Unauthorized method executes — server only
   checks auth on the primary documented method.

   Record: Per-method findings.

8. **HTTP-method override header probe**
   [Hacking APIs, Ch 10]

   Do: Some APIs honor `X-HTTP-Method-Override: DELETE` or
   `_method=DELETE` body parameter. Test whether method override
   bypasses an authorization check that's keyed on the actual
   method.

   Vulnerable response: Override parsed, authorization bypassed.

### Phase 4: A-B-A Modification Verification

9. **Write-BOLA verification**
   [Hacking APIs, Ch 10, p. 227]

   Do: For endpoints that modify state (PUT / PATCH / DELETE),
   repeat Phase 2 with state-changing methods:
   - As `{user_a}`, capture baseline of a harmless field (e.g.,
     `description`)
   - As `{user_b}`, PUT/PATCH the same resource with a modified
     description
   - As `{user_a}`, GET the resource — did user B's modification
     persist?

   Vulnerable response: User B's modification visible in user A's
   view — write access bypass.

   Not-vulnerable response: 403 on user B's request, or user A
   sees unchanged resource.

   Record: Findings with all 3 steps as evidence; severity raised
   one level over read-only BOLA.

   **Immediately revert** any change made during this test.

### Phase 5: BFLA on Admin Write Operations (Gated)

10. **Admin write endpoint probe (proof-only)**
    [Hacking APIs, Ch 10, p. 227]

    Do: For admin write endpoints (e.g., `POST /api/admin/invite`,
    `PUT /api/admin/roles`), test with `{user_a}`.

    NEVER actually submit a destructive payload. Send a syntactically
    minimal request that the server must reject if authorization
    is enforced:
    ```
    POST /api/admin/invite
    Authorization: Bearer {user_a_token}
    Content-Type: application/json

    {}
    ```

    Vulnerable response: 200 or 400-with-validation-error (either
    way, the endpoint accepted the request through the auth layer
    — BFLA confirmed).

    Not-vulnerable response: 401 / 403 (rejected at auth layer
    before validation).

    Record: Per-endpoint findings. Severity Critical for
    invite/role/delete endpoints.

## Payload Library

Categories:

- **A-B token pairs**: `{user_a_token}` with `{user_b_id}` in the
  ID location, and vice versa
- **Array wrappers**: `[{id}]` for endpoints expecting scalars
- **Side-channel ID probes**: `id=1` / `id=999999999` / `id=0`
- **Admin endpoints**: `/api/admin/*`, `/api/internal/*`,
  `/api/manage/*` path list
- **Method-swap set**: per-endpoint `GET/POST/PUT/PATCH/DELETE`
  fuzz
- **Method-override headers**: `X-HTTP-Method-Override`,
  `_method`, `X-Method`

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-639 for BOLA. CWE-285 for BFLA. CWE-269 (Improper
  Privilege Management) for admin-function bypass. CWE-200 for
  side-channel ID enumeration.
- **OWASP**: For APIs: API1:2023 (BOLA). API5:2023 (BFLA).
  API3:2023 (BOPLA for property-level escalation; cross-reference
  mass-assignment-hunter).
- **CVSS vectors**: read-BOLA on PII —
  `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`. Write-BOLA —
  `...C:H/I:H/A:N`. Admin-function BFLA with mass impact —
  `...PR:L/S:C/C:H/I:H/A:H`.
- **Evidence**: for BOLA, the A-baseline + B-with-A-ID
  request/response pair + diff. For BFLA, the regular-user token
  + admin-endpoint response. For write-BOLA, all 3 A-B-A steps.
- **Remediation framing**: backend engineer. Include:
  - Centralized authorization middleware snippets (e.g., Django
    `@permission_required`, Rails Pundit, Express
    `casbin`, Spring `@PreAuthorize`)
  - Deny-by-default route configuration
  - Controller-inheritance pattern (admin controllers inherit
    from a base that enforces role checks)
  - Consistent HTTP-method authorization (same check on GET,
    POST, PUT, PATCH, DELETE)

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every BOLA finding includes the A-baseline AND B-with-A-ID
      request/response pair
- [ ] Every BFLA finding shows the regular-user token in the
      request headers
- [ ] Write-BOLA findings include the full A-B-A verification
      chain
- [ ] Any state changes made during write-BOLA tests were
      reverted (or escalated to the owner for revert)
- [ ] No admin function was actually executed beyond what proof
      requires
- [ ] No production-customer resources were queried
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Public resources misread as BOLA**: Some resource IDs refer to
  intentionally-public objects (public profiles, marketing pages,
  published articles). Cross-reference with documentation before
  filing.

- **Redacted but returned data**: Some APIs return 200 with
  fields masked (`"email": "***@***.com"`). The caller sees
  "success" but no sensitive data. Distinguish by checking if
  non-sensitive fields (timestamps, IDs) match the target
  account — redaction is a correct defense.

- **Cache-served responses**: A response may come from a CDN /
  proxy cache, not the origin. `Age:` or `X-Cache:` headers
  confirm. The underlying endpoint may be correct; the cache is
  the bug (cross-reference `cache-smuggling-hunter`).

- **Soft-delete records**: Some apps return 200 with a tombstoned
  record for deleted resources. Confirm the response has the
  EXPECTED user's data, not just 200-OK status.

- **Admin impersonation features**: Support staff legitimately
  access other users' data via "impersonate" tooling. Exclude
  those sessions from test inputs.

- **405 vs 403 signal confusion**: Method-swap BFLA may return
  405 (Method Not Allowed) which looks like a rejection. But 405
  on a method-swap means the method-routing layer rejected, not
  the auth layer. Test other methods that ARE routed but
  unauthorized (different API path variant) to probe auth layer
  specifically.

## References

External:
- OWASP API1:2023: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP API5:2023: https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- CWE-639: https://cwe.mitre.org/data/definitions/639.html
- CWE-285: https://cwe.mitre.org/data/definitions/285.html
- WSTG-ATHZ-03: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia Essencial de Segurança em APIs_ BOLA e BFLA.md`

Grounded in:
- Hacking APIs, Ch 3 + Ch 10 (API Authorization)
- OWASP WSTG v4.2 (WSTG-ATHZ-04, WSTG-ATHZ-03)
- OWASP API Security Top 10 (API1:2019, API5:2019, API1:2023,
  API5:2023)
- Bug Bounty Bootcamp, Ch 10 (IDOR/BOLA case studies)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
