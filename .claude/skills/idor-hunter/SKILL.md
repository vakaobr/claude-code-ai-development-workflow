---
name: idor-hunter
description: "Systematic testing for Insecure Direct Object Reference (IDOR) vulnerabilities in web applications. Use when auditing endpoints that expose resource identifiers in URLs, body parameters, headers, or cookies; when a multi-tenant app grants object access based on request-supplied IDs; or when the orchestrator identifies object-ID parameters during API recon. Produces findings with CWE-639 mapping, per-endpoint PoC request pairs, and developer-facing remediation. Defensive testing only, against assets listed in .claude/security-scope.yaml."
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
  source_methodology: "Guia Completo de Testes e Mitigação de IDOR.md"
  service_affecting: false
  composed_from: []
---

# IDOR Hunter

## Goal

Test authenticated endpoints for Insecure Direct Object Reference flaws —
cases where the application grants access to a resource based on a
client-supplied identifier without verifying that the current user is
authorized to access that specific resource. This skill implements the
WSTG-ATHZ-04 methodology and maps findings to CWE-639 and OWASP ASVS V4.2.
The goal is to give the engineering team a concrete list of endpoints that
need object-level authorization checks added, with copy-pasteable
remediation code for the frameworks in use (Laravel, Django, Express).

## When to Use

- The target exposes endpoints with numeric, sequential, or predictable
  object IDs in URLs, request bodies, headers, or cookies.
- The target is a multi-tenant application where users should only see
  their own resources (orders, invoices, documents, messages).
- API recon (via `api-recon` or `web-recon-active`) surfaced endpoints that
  accept `user_id`, `account_id`, `document_id`, or similar parameters.
- Authentication is in place but per-object authorization logic is unclear
  from code review.
- The orchestrator selects this skill after `attack-surface-mapper`
  identifies authenticated endpoints with resource ID parameters.

## When NOT to Use

- For API endpoints where the access-control flaw is at the *function*
  level (admin-only endpoint callable by any user) — use
  `bola-bfla-hunter` instead, specifically for BFLA.
- For purely public endpoints with no authentication — IDOR requires an
  authenticated baseline.
- For missing authentication entirely — use `auth-flaw-hunter`.
- For parameter tampering that affects pricing or business workflow logic
  — use `business-logic-hunter`.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or doesn't
   parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND its
   `testing_level` is `active`.
3. IDOR testing requires two authenticated sessions for different users.
   Confirm both sets of test credentials are approved for this asset —
   check `requires_auth_testing_credentials` and
   `test_credentials_vault_path` in the scope file.
4. If the target is ambiguous, write it to
   `.claude/planning/{issue}/SCOPE_QUESTIONS.md` and halt for that target
   only.
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with
   status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name (e.g., `security-audit-q2-2026`)
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific endpoints/parameters to focus on
- `{user_a}`: credentials or session token for test user A
- `{user_b}`: credentials or session token for test user B
  (different role/tenant preferred)
- `{user_admin}`: optional — admin credentials for vertical escalation
  tests

If any required credential is missing, halt and request it before
proceeding.

## Methodology

### Phase 1: Map Object Reference Endpoints

1. **Inventory ID-bearing parameters** [Bug Bounty Bootcamp, Ch 10, p. 182]

   Do: Read the `.claude/planning/{issue}/API_INVENTORY.md` produced by
   `api-recon`. Extract every endpoint whose path, query, body, header, or
   cookie contains a parameter matching the patterns: `*_id`, `*Id`,
   `*uuid`, `*Uuid`, numeric path segments like `/users/123/...`, or
   base64-encoded values that decode to integers or UUIDs.

   If no inventory exists: halt and request that `api-recon` or
   `web-recon-active` be run first.

   Record: Write the parameter inventory to
   `.claude/planning/{issue}/idor-targets.md`.

2. **Classify reference types** [WAHH, Ch 8, p. 267]

   For each parameter, classify as: sequential integer, UUID v4, hash
   (sha/md5), base64-encoded, or opaque token. Sequential integers and
   base64-wrapped integers are highest-yield targets; opaque tokens are
   lowest.

   Record: Append reference type to each entry in `idor-targets.md`.

### Phase 2: Baseline Access Patterns

3. **Authenticate as user A and capture baseline** [WSTG v4.2, WSTG-ATHZ-04]

   Do: For each target endpoint, make the request authenticated as
   `{user_a}` with their own resource ID. Capture the full response.

   Vulnerable response (later): Same response when authenticated as
   `{user_b}` but using A's resource ID.

   Not-vulnerable response (later): 401, 403, 404, or a response whose
   body differs in a way consistent with "resource doesn't exist for this
   user".

   Record: Store baseline responses in
   `.claude/planning/{issue}/idor-baselines/`.

### Phase 3: Horizontal Access Tests

4. **Cross-user horizontal IDOR** [Bug Bounty Playbook V2]

   Do: Replay each baseline request, but authenticated as `{user_b}`,
   keeping A's resource IDs unchanged. Diff the response.

   Vulnerable response: Status 200 with content matching user A's baseline
   — user B can read user A's resource.

   Not-vulnerable response: 401, 403, 404, or response content that does
   not match user A's baseline (e.g., "resource not found").

   Record: Append FINDING-NNN to SECURITY_AUDIT.md for each vulnerable
   endpoint. Include both the A-baseline request and the B-with-A-ID
   request in evidence.

5. **ID enumeration and prediction** [Hacking APIs, Ch 10, p. 191]

   Do: If references are sequential integers, test IDs adjacent to
   known-owned ones (e.g., `user-1234` → test 1233, 1235, and ±10). For
   UUIDs, test whether the server leaks UUIDs of unrelated resources in
   error messages, verbose responses, or redirect URLs.

   Vulnerable response: Adjacent ID returns 200 with another user's data;
   or UUID leaks in errors then that UUID is accessible.

   Record: For any leaked reference that's later accessible, create a
   chained FINDING-NNN citing both the information disclosure and the
   IDOR.

6. **IDOR via alternate transports**
   [zseano's methodology, p. 1349]

   Do: For each endpoint, test the same operation via:
   - Different HTTP methods (GET vs POST vs PUT vs PATCH vs DELETE)
   - Parameter in body vs query vs header vs cookie
   - Content-Type variants (JSON vs form-encoded vs multipart)

   Vulnerable response: An authorization check present on the primary
   transport is missing on an alternate.

   Record: Findings for each unchecked alternate transport.

### Phase 4: Vertical and Role Escalation

7. **Role-scoped IDOR** [WAHH, Ch 8, p. 267]

   Do: For endpoints that exist only for privileged roles (admin,
   moderator, billing-admin), test whether `{user_a}` (regular user) can
   invoke them by guessing the URL or replaying a captured admin request
   with their own session.

   Vulnerable response: Regular user gets a 200 on what should be an
   admin-only endpoint.

   Record: Findings marked as vertical privilege escalation (CWE-269 in
   addition to CWE-639).

### Phase 5: State-Changing IDOR

8. **Write/update/delete IDOR** [Bug Bounty Bootcamp, Ch 10, p. 183]

   Do: For endpoints that modify state (POST, PUT, PATCH, DELETE), repeat
   Phase 3 tests but with user B attempting to modify user A's resources.
   Use minimally-destructive payloads — prefer updating a harmless field
   (e.g., `description`) over deleting.

   Vulnerable response: Modification succeeds (200/204), and a subsequent
   GET as user A shows the modification.

   Record: Findings for each state-changing IDOR, severity raised one
   level compared to read-only IDOR.

### Phase 6: Indirect IDOR Patterns

9. **IDOR via filename/path** [Bug Bounty Bootcamp, Ch 10]

   Do: For file upload/download endpoints, test whether filenames, upload
   IDs, or path parameters can reference other users' files. Also test
   file-extension fuzzing (e.g., `receipt_id=2983` → `receipt_id=2983.json`,
   `.xml`, `.pdf`) — some endpoints return richer data in alternate
   formats.

10. **Unauthenticated access probe** [WSTG v4.2, WSTG-ATHZ-02]

    Do: For each endpoint, repeat the A-baseline request with no session
    cookie / no Authorization header.

    Vulnerable response: The endpoint returns data without authentication
    (missing auth altogether is worse than IDOR).

    Not-vulnerable response: 401/403/redirect to login.

    Record: If unauth access works, file as a higher-severity
    authentication failure (CWE-306) and cross-reference `auth-flaw-hunter`
    — the IDOR is moot because the endpoint is effectively public.

## Payload Library

Payloads for this skill are documented in `references/payloads.md`.
Categories:

- **ID substitution templates**: request skeletons for each parameter
  location (URL, body, header, cookie)
- **ID prediction sequences**: ±N from known IDs, sibling UUIDs, common
  admin IDs (1, 0, -1, null)
- **Relay ID decode/encode**: GraphQL base64 relay ID manipulation
- **Extension fuzzing list**: common variant extensions that return
  richer data (`.json`, `.xml`, `.csv`, `.pdf`, `.html`, `.txt`)

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per the
schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-639 (Authorization Bypass Through User-Controlled Key).
  Add CWE-269 for role-escalation variants. Add CWE-306 when
  unauthenticated access is possible.
- **OWASP**: WSTG-ATHZ-04. For APIs, additionally map to API1:2023
  (Broken Object Level Authorization).
- **CVSS vectors**: typically `AV:N/AC:L/PR:L/UI:N` — vary S, C, I, A
  based on what the vulnerable endpoint exposes.
- **Evidence**: the A-baseline request/response pair, the B-attacking-A
  request/response pair, and a diff showing the authorization failure.
- **Remediation framing**: backend engineer who owns the endpoint.
  Include framework-specific code in `references/remediation.md` for
  Laravel (policies, Gate), Django (get_object with user filter),
  Express (middleware pattern).

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every finding has a baseline (user A, own resource) AND an attack
      request (user B, user A's resource) in evidence
- [ ] Every finding has a CWE-639 mapping minimum
- [ ] Remediation snippets match the tech stack declared in the scope
      file for this asset (no Laravel code for a Django app)
- [ ] No finding was produced against an asset not in scope
- [ ] No out-of-scope IDs were iterated — if we discovered IDs for
      third-party resources, they're not in findings
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`
- [ ] If we tested state-changing IDOR, all destructive tests were
      reverted (the description field we changed is reverted)

## Common Issues

- **Different response sizes due to personalization**: User A's dashboard
  has 12 widgets, user B's has 8 — a response size diff doesn't prove
  authorization bypass. Compare response structure, not just size.

- **Soft-deleted resources returning 200**: Some apps return cached or
  soft-deleted records even when access control should deny. Confirm by
  checking whether the resource is actually owned by the requesting user
  in the response body, not just the HTTP status.

- **Per-user data masking**: Some frameworks return 200 with a redacted
  response when access is denied. Look for `"email": "***@***.com"` or
  `"[REDACTED]"` — not a vulnerability.

- **Public resources**: The ID refers to a resource intended to be public
  (public user profile, marketing document). Filing these creates noise —
  confirm sensitivity with the product team first.

- **Optimistic caching**: CDN/cache layers may serve one user's response
  to another without the app ever seeing the request. This is a caching
  bug (see `cache-smuggling-hunter`), not an IDOR — distinguish by
  checking cache headers and comparing origin responses.

- **Admin-impersonation sessions**: Support staff can legitimately access
  other users' resources via support tooling. Exclude these sessions from
  testing or they'll generate false positives.

## References

- `references/payloads.md` — ID substitution templates and prediction
  sequences
- `references/remediation.md` — framework-specific authorization code
  snippets (Laravel Gates/Policies, Django permissions, Express
  middleware)

External:
- WSTG-ATHZ-04: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
- CWE-639: https://cwe.mitre.org/data/definitions/639.html
- OWASP API1:2023 (BOLA): https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia Completo de Testes e Mitigação de IDOR.md`

Grounded in:
- The Web Application Hacker's Handbook, Ch 8 (Attacking Access Controls)
- Bug Bounty Bootcamp, Ch 10 (IDOR)
- Bug Bounty Playbook V2 (Authorization chapter)
- Hacking APIs, Ch 10 (API Authorization)
- OWASP WSTG v4.2 (ATHZ-04, ATHZ-02)
- zseano's methodology (Alternate transport testing)

Conversion date: 2026-04-23
Conversion prompt version: 1.0
