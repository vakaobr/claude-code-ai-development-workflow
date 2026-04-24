---
name: rate-limit-hunter
description: "Tests APIs and sensitive features for missing or weak rate limiting — credential-stuffing resistance, MFA code brute-force, SMS / email amplification, oversized-payload resource exhaustion, and IP / session rotation evasion. Use when the target has login / password-reset / MFA / signup / SMS-trigger endpoints and `api-recon`'s auth inventory shows no `X-RateLimit-*` response headers; when the orchestrator identifies high-cost operations; or when cross-referencing a `auth-flaw-hunter` lockout finding. Produces findings with CWE-307 / CWE-770 / CWE-400 mapping and throttle / captcha / resource-limit remediation. Defensive testing only, against assets listed in .claude/security-scope.yaml — service_affecting: true."
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
  source_methodology: "Guia de Segurança_ Escassez de Recursos e Limitação de Taxa.md"
  service_affecting: true
  composed_from: []
---

# Rate Limit Hunter

## Goal

Test the target's sensitive endpoints and high-cost features for missing
or weak rate limiting — the class of flaws that lets an attacker brute-
force credentials, burn through MFA codes, send mass SMS / email (often
at the org's direct cost), scrape bulk data, or trigger resource
exhaustion via oversized payloads. This skill implements WSTG-ATHN-03
and WSTG-BUSL-05 and maps findings to CWE-307 (Improper Restriction of
Excessive Authentication Attempts), CWE-770 (Allocation of Resources
Without Limits or Throttling), and CWE-400 (Uncontrolled Resource
Consumption). The goal is to give the team a concrete list of
unprotected endpoints with observed throughput ceilings and remediation
patterns (token-bucket, sliding-window, CAPTCHA escalation,
infrastructure limits).

## When to Use

- The target has login, password-reset, MFA-verification, signup, SMS /
  email-trigger, or bulk-data endpoints.
- Responses lack `X-RateLimit-Limit`, `X-RateLimit-Remaining`,
  `Retry-After`, or similar headers during normal use.
- `api-recon` flagged `no_rate_limit_headers: true` in the `API
  Inventory.md` auth section.
- `auth-flaw-hunter` identified a login endpoint with no observable
  lockout.
- The orchestrator selects this skill after detecting high-cost
  operations (SMS-send, file-processing, complex queries).

## When NOT to Use

- For pure DoS / DDoS flooding — rate-limit testing is a controlled
  burst to characterize the limit, not a denial-of-service attack.
  If scope requires DoS testing, use a dedicated stress tool under
  separate authorization.
- For algorithmic-complexity DoS (regex backtracking, quadratic JSON
  parsing) — that's `deserialization-hunter` or a dedicated
  algorithmic-complexity skill.
- For business-logic abuse that doesn't involve request volume
  (e.g., applying a coupon twice) — use `business-logic-hunter`.
- Any asset not listed in `.claude/security-scope.yaml`, or whose
  `service_affecting` is `denied`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or
   doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND its
   `testing_level` is `active`.
3. This skill's `service_affecting: true` flag is load-bearing.
   Confirm the asset's `service_affecting` is `approved` in the scope
   file. If `denied`, halt and request per-run approval from the
   asset owner. Cite the specific endpoints to be tested.
4. Apply the scope's `rate_limit_rps` as a CEILING. This skill's
   purpose is to probe how the target responds AT the documented
   ceiling — do not exceed it. If the target's actual defense kicks
   in at a higher threshold, that's a finding; we don't need to
   flood past the scope ceiling to prove it.
5. For SMS / email trigger endpoints specifically: do not trigger
   real SMS sends to real phone numbers even on in-scope assets.
   Use only test-account phone numbers explicitly listed in the
   scope file's `test_contacts` section.
6. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with
   status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific endpoints to probe
- `{user_a}`: credentials for a test user (needed to trigger
  authenticated rate-limit probing)
- `{test_contacts}`: SMS/email test destinations from the scope file

## Methodology

### Phase 1: Baseline and Header Inventory

1. **Establish baseline performance** [Hacking APIs, Ch 9, p. 241]

   Do: For each target endpoint, send 10 legitimate requests at ~1/sec.
   Record: mean response time, status code, body length, and ALL
   response headers (especially rate-limit hints).

   Record: `.claude/planning/{issue}/rate-limit-baselines.md`.

2. **Audit rate-limit response headers** [Hacking APIs, Ch 13, p. 190]

   Do: Inspect each baseline response for the presence of:
   - `X-RateLimit-Limit`, `X-RateLimit-Remaining`,
     `X-RateLimit-Reset`
   - `RateLimit`, `RateLimit-Policy`, `Retry-After`
   - `X-Rate-Limit-*` (legacy vendor variants)
   - Custom headers like `X-Shopify-Api-Call-Limit`

   Vulnerable response: No headers present — no advertised limit.

   Not-vulnerable response: Headers present with sensible values
   (e.g., "remaining: 99" / "limit: 100 per 60s").

   Record: Header matrix per endpoint.

### Phase 2: Frequency Threshold (Scope-Ceiling-Bound)

3. **Probe login endpoint for attempt-count lockout**
   [OWASP API Security Top 10, p. 10; WSTG v4.2, 4.4.3]

   Do: For the login endpoint with a known test account that can be
   locked safely (`{user_a}`), submit intentionally incorrect
   passwords at `{rate_limit_rps}` rps up to a ceiling of 30
   attempts.

   Vulnerable response: 30 attempts complete without lockout, CAPTCHA,
   or 429.

   Not-vulnerable response: Account locked, CAPTCHA triggered, or
   429 after a small number of failures (typically 5-10).

   Record: Exact attempt number at which any defense kicked in (or
   "none observed after 30").

   **Important**: After this test, restore the account access via
   the documented recovery flow; if unattended lockout would block
   the rest of the assessment, halt here and escalate.

4. **Probe MFA-code endpoint for brute-force**
   [OWASP API Security Top 10, p. 10]

   Do: If MFA codes are numeric (4-6 digits), calculate the
   brute-force space (10,000 for 4-digit, 1,000,000 for 6-digit).
   Submit 100 wrong codes against a controlled test account's
   pending MFA challenge.

   Vulnerable response: 100 wrong attempts complete without lockout
   or CAPTCHA. At observed rate, 10,000 attempts (full 4-digit
   space) would complete in minutes.

   Not-vulnerable response: Challenge invalidated / session forced
   to restart after 3-5 wrong codes.

   Record: Attempt-to-lockout ratio.

### Phase 3: Payload-Size Resource Exhaustion

5. **Oversized `limit` / `size` / `page_size` parameters**
   [OWASP API Security Top 10, p. 14]

   Do: For endpoints with `?limit=` or `?page_size=` parameters,
   submit successively larger values: 100, 1000, 10000, 100000,
   1000000, 999999999999.

   Watch response time and status. STOP at first:
   - Response > 10 seconds (potential DoS confirmation — don't
     deepen)
   - 500 error suggesting memory exhaustion
   - Response > 50MB (mass-data-scrape risk)

   Vulnerable response: Any of the above — server didn't enforce a
   maximum.

   Not-vulnerable response: 400 Bad Request, or silent truncation
   to documented maximum.

   Record: Threshold at which behavior becomes abnormal.

6. **Oversized string / body probes** [Hacking APIs, Ch 9, p. 233]

   Do: For endpoints accepting text fields, submit strings of
   increasing size (1KB → 10KB → 100KB → 1MB → 10MB). Observe
   response time, memory-hint errors, or truncation behavior.

   Vulnerable response: Server accepts and processes 10MB strings,
   or returns 500 with OOM-like error.

   Record: Per-field maximum accepted size.

7. **JSON array / nested-object probes** [OWASP API, p. 15]

   Do: For JSON-accepting endpoints, submit arrays of increasing
   length (`{"items": [1, 2, ... 100000]}`) and nested objects of
   increasing depth (10 → 50 → 100 levels deep).

   Vulnerable response: Server parses without a schema-level limit.

   Record: Array/nesting limit per endpoint.

### Phase 4: Business-Logic Limits

8. **One-time-function reuse** [WSTG v4.2, 4.10.5]

   Do: For documented one-time operations (coupon code, free trial
   signup with same email, single-use OTP), attempt to invoke the
   operation twice in the same session.

   Vulnerable response: The operation succeeds both times — the
   "one-time" enforcement is client-side only.

   Record: Each successful reuse as a finding; severity depends on
   the economic impact.

### Phase 5: Evasion Probing (Confirms the Defense, Not Breaks It)

9. **IP / session rotation** [Hacking APIs, Ch 13, p. 270]

   Do: IF a rate-limit defense was observed in Phase 2, try evasion:
   - Set `X-Forwarded-For: 127.0.0.1` (or increment per request)
   - Set `X-Client-IP` / `X-Real-IP` / `CF-Connecting-IP`
   - Rotate the session cookie (logout + login between bursts)
   - Rotate the API key (if test account has multiple)
   - Distribute across different source IPs (requires scope-approved
     pivoting infrastructure — skip if not)

   Vulnerable response: The limit resets when the identifier
   changes — the server relied on a weak identifier.

   Not-vulnerable response: Limit persists based on session token,
   user ID, or composite fingerprinting.

   Record: Which identifier the limit is bound to; weaker bindings
   are higher severity.

### Phase 6: SMS / Email Cost Amplification (Gated)

10. **SMS / email trigger endpoint** [OWASP API Security Top 10]

    Do: ONLY if the scope file explicitly lists `test_contacts` for
    SMS/email, and ONLY to those contacts. Trigger 3 sends in rapid
    succession to a test contact.

    Vulnerable response: 3 sends completed — no per-recipient rate
    limit. Multiply by average cost ($0.01-$0.05/SMS) and monthly
    org volume for a financial-impact estimate.

    Not-vulnerable response: Second or third send deferred with
    "please wait N seconds" or 429.

    Record: Finding severity depends on per-unit cost AND ease of
    reaching the endpoint without auth (unauth is worse).

## Payload Library

Categories:

- **Login brute-force**: incorrect-password list targeting
  controlled accounts
- **MFA brute-force**: numeric 4-6 digit space walks
- **Oversized numerics**: `999999999999`, scientific notation
- **Oversized strings**: repeated-character blocks up to 10MB
- **JSON array stress**: arrays up to 100K elements
- **Nested-JSON probes**: depth 10 → 100
- **IP-spoofing headers**: `X-Forwarded-For`, `X-Client-IP`,
  `CF-Connecting-IP`, `True-Client-IP`

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-307 (Improper Restriction of Excessive Authentication
  Attempts) for auth/MFA brute-force. CWE-770 for unbounded
  resource allocation. CWE-400 for bulk data / oversized payloads.
  CWE-837 (Improper Enforcement of a Single, Unique Action) for
  one-time-function reuse.
- **OWASP**: For APIs, API4:2023 (Unrestricted Resource Consumption).
  For web apps, WSTG-ATHN-03 and WSTG-BUSL-05. A04:2021 (Insecure
  Design).
- **CVSS vectors**: unprotected login enabling credential stuffing —
  `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`. Unprotected SMS trigger —
  `...C:N/I:N/A:H` (cost-based DoS). Unlimited `limit=` parameter —
  `...C:H/I:N/A:L` (mass-scrape + resource pressure).
- **Evidence**: the exact request used, the observed throughput (N
  requests in M seconds), and the response that didn't block
  (status + sampled body).
- **Remediation framing**: platform/backend engineer. Include:
  - Token-bucket or sliding-window snippets (Redis-backed; `ioredis`
    for Node, `redis-py-cluster` for Python)
  - CAPTCHA escalation pattern (passive first N attempts, CAPTCHA
    after threshold)
  - Per-account + per-IP dual-binding (defeats IP rotation AND
    session rotation)
  - Per-recipient SMS throttling (not just per-sender)
  - API gateway rate-limit config (Kong, Tyk, AWS API Gateway
    usage plans)

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every probe stayed at or under the scope's `rate_limit_rps`
      ceiling — confirmed by measuring actual request rate
- [ ] SMS/email probes used only `test_contacts` from the scope
- [ ] Controlled test accounts used for lockout probing were
      restored (or escalated if unrestorable)
- [ ] No real user was locked out; no real customer received an
      SMS from the probe
- [ ] Each finding reports observed throughput (N req / M sec), not
      just "no rate limit"
- [ ] Evasion findings note which specific identifier the limit
      was bound to
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Tooling saturation mistaken for server-side limit**: Your
  testing tool caps at 100 rps but the server allows 400. You see
  a plateau and misread it as the server's limit. Run from a
  higher-throughput rig or note that the measured ceiling is a
  tool limit, not a server defense.

- **CDN / proxy cache**: Responses are served from a CDN cache
  without reaching the origin. Requests all succeed but the origin
  never saw them. Add a cache-busting query parameter
  (`?_=<timestamp>`) to force origin hits for each probe.

- **Trusted infrastructure whitelist**: Testers running from a
  trusted VPN or corporate network are often exempt from production
  rate limits. Confirm the probe origin is subject to the same
  defenses as a random internet client. If not, note the test as
  inconclusive for external-attacker scenarios.

- **429 returned but action still completed**: Some apps return 429
  with the body from the successful action already applied — they
  rate-limit the response but not the operation. Always check
  whether the operation's side effects happened, not just whether
  the response was 429.

- **Lockout that unblocks too fast**: The server does implement
  lockout but for only 60 seconds. Real attackers with unlimited
  time can simply wait and retry. Note this as a finding
  (insufficient lockout duration) — Medium severity.

- **Rate limit enforced on HTTP only, not on websocket / gRPC /
  other channels**: Inconsistent enforcement across transports is
  a finding. Cross-reference `api-recon`'s transport inventory.

## References

External:
- WSTG-ATHN-03: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism
- WSTG-BUSL-05: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_be_Used_Limits
- OWASP API4:2023: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- CWE-307: https://cwe.mitre.org/data/definitions/307.html
- CWE-770: https://cwe.mitre.org/data/definitions/770.html

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia de Segurança_ Escassez de Recursos e Limitação de Taxa.md`

Grounded in:
- Hacking APIs, Ch 13 (Rate Limit Testing)
- Bug Bounty Bootcamp, Ch 24-25
- OWASP WSTG v4.2 (WSTG-ATHN-03, WSTG-BUSL-05)
- OWASP API Security Top 10 (API4:2019, API4:2023)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
