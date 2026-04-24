---
name: business-logic-hunter
description: "Tests application-specific logic for workflow bypasses (skipping steps), data-validation gaps (negative prices, oversized quantities, unit confusion), hidden-field tampering, function-usage abuse (coupon reuse, free-trial re-registration), and trust-boundary pivots. Use when the target has complex multi-step workflows (checkout, account recovery, approval chains), parameters with real-world meaning (prices, quantities, dates), or state-carrying hidden fields. This class is unique to each app — requires understanding of intended business rules. Produces findings with CWE-840 / CWE-841 mapping and server-side-authoritative-validation remediation."
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
  subcategory: logic
  authorization_required: true
  tier: T1
  source_methodology: "Guia de Vulnerabilidades em Lógica de Negócios.md"
  service_affecting: false
  composed_from: []
---

# Business Logic Hunter

## Goal

Test application-specific logic for flaws that arise from violated
developer assumptions — workflow bypasses, logically-invalid-but-
technically-valid data (negative prices, oversized quantities,
unit-confusion), hidden-field tampering, function-usage abuse (coupon
reuse), and trust-boundary pivots (recovery flow granting login-like
state). Unlike technical vulnerabilities, logic flaws are unique to
each application and require context. This skill implements WSTG-BUSL
and maps findings to CWE-840 (Business Logic Errors) and CWE-841
(Improper Enforcement of Behavioral Workflow). The goal is to hand
the product + backend team a concrete list of workflow and
data-validation gaps with server-side-authoritative remediation.

## When to Use

- The target has complex multi-step workflows: checkout, account
  recovery, approval chains, subscription changes, multi-party
  transactions.
- Parameters encode real-world meaning: prices, quantities,
  currency codes, dates, units, tenure.
- Hidden form fields or API properties carry state that could be
  tampered (`user_role`, `price`, `approvalStatus`, `step`).
- One-time / limited-use functions exist: coupon codes, free-trial
  eligibility, referral rewards, one-per-household offers.
- Data "hand-off" points exist between systems (e.g., inventory
  system → pricing → checkout) that may trust each other.
- The orchestrator selects this skill after `api-recon` surfaces
  workflow inventory.

## When NOT to Use

- For generic input-validation flaws (SQLi, XSS, command injection)
  — use the class-specific hunter.
- For missing access control (user reaching another user's data) —
  use `idor-hunter` / `bola-bfla-hunter`.
- For mass-assignment / admin-flag injection in generic
  profile-update endpoints — use `mass-assignment-hunter`.
- For rate-limit-specific abuse (e.g., SMS cost amplification,
  brute-force) — use `rate-limit-hunter`.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or
   doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND its
   `testing_level` is `active`.
3. Business-logic testing triggers real workflow actions: creating
   orders, using coupons, consuming trial offers. Use ONLY:
   - Test accounts and test billing instruments (test credit cards,
     test SMS numbers from the scope)
   - Reversible actions (cancel the order immediately after
     creation; consume test coupons that have no real value)
4. For financial-impact findings (negative price, oversized credit,
   coupon-reuse): STOP at the first confirmation. Do NOT escalate
   to see "how much" can be stolen — one proof is enough.
   Coordinate revert with the platform team.
5. For workflow-bypass findings that create persistent records
   (KYC-skip, approval-skip), file the finding AND request that
   the record be cleared from the production DB.
6. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with
   status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: the workflows to test (e.g., "checkout",
  "account-recovery", "subscription-change")
- `{user_a}`: test-user credentials
- `{user_b}`: second test-user credentials (for cross-user logic
  tests)
- `{test_billing}`: test credit-card / payment instrument from scope
- `{workflow_docs}`: optional — links to product-team
  documentation describing intended workflows

## Methodology

### Phase 1: Workflow Mapping

1. **Trace the target workflow end-to-end** [Hacking APIs, Ch 7, p. 166]

   Do: Execute the workflow once as `{user_a}` through the UI / API
   with all steps completed normally. Capture every HTTP request:
   method, path, request body, response status, state carried
   forward.

   Record: `.claude/planning/{issue}/workflow-traces/{workflow}/happy-path.har`
   and a human-readable summary in
   `.claude/planning/{issue}/workflow-traces/{workflow}/summary.md`.

2. **Identify state-carrying parameters** [WAHH, Ch 11, p. 410]

   Do: For each step, identify what state is carried forward:
   - Session cookies or JWTs (handled by `session-flaw-hunter` /
     `jwt-hunter`)
   - Explicit `step` / `stage` / `phase` parameters in URLs or
     bodies
   - Hidden form fields (`<input type="hidden" name="price"
     value="10">`)
   - URL parameters encoding state (`/checkout?amount=10.00&
     currency=USD`)
   - Referer-based navigation logic

   Record: State-inventory matrix per workflow.

### Phase 2: Workflow Bypass

3. **Step-skipping probe**
   [WSTG v4.2, WSTG-BUSL-06]

   Do: Execute the workflow up to step N, then skip to step N+2
   (or the final "success" step) directly. Try:
   - Directly GET / POST to the URL of step N+2 without completing
     step N+1
   - Submit a step-N+2 request with state captured from step N
     (not N+1)
   - Replay step N's response-provided redirect-URL but with a
     later step's expected body

   Vulnerable response: The application treats the workflow as
   completed — e.g., the user gets an "order confirmed" page
   without payment processed.

   Not-vulnerable response: The server rolls back, redirects to
   the missing step, or returns 403.

   Record: Per-skip FINDING-NNN.

4. **Out-of-order step probe**
   [WAHH, Ch 11]

   Do: Submit step N+1 BEFORE step N.

   Vulnerable response: Step N+1 processes using incomplete state
   (e.g., placing an order before adding items to cart).

   Record: Findings.

### Phase 3: Logical Data Validation

5. **Negative / zero / boundary values**
   [WSTG v4.2, WSTG-BUSL-01]

   Do: For fields representing quantities, prices, durations,
   unit counts, try:
   - Negative: `-1`, `-100`, `-999999`
   - Zero: `0`
   - Very large: `999999999999`
   - Non-integer where integer expected: `1.5` for a count
   - Unicode numeric characters: `١٢٣` (Arabic), `一二三` (Chinese)

   For price specifically, a negative price can result in a
   NEGATIVE charge (refund) at checkout.

   Vulnerable response: The app accepts and applies the logically-
   invalid value.

   Not-vulnerable response: 400 Bad Request with range validation
   error.

   Record: Per-field FINDING-NNN.

6. **Unit / currency confusion**
   [WAHH, Ch 11]

   Do: For pricing or measurement endpoints, try:
   - Submit price in a different currency than expected (e.g.,
     `{"price": 100, "currency": "IDR"}` when the backend
     assumes USD)
   - Submit weight in ounces where the backend assumes grams
   - Submit prices with different decimal conventions (12.50 vs
     12,50)

   Vulnerable response: The server uses the submitted currency /
   unit without re-validation against the user's region or the
   product's defined currency.

   Record: FINDING-NNN — often leads to 100x or 1000x price
   errors.

### Phase 4: Hidden-Field Tampering

7. **Edit-hidden-fields probe**
   [WSTG v4.2, WSTG-BUSL-03]

   Do: For each hidden form field or state-carrying URL / body
   parameter identified in Phase 1:
   - Flip booleans: `hasPaid=false` → `hasPaid=true`;
     `approvalRequired=true` → `false`
   - Change numerics: `price=10.00` → `price=0.01`;
     `quantity=1` → `quantity=1000`
   - Change references: `cartId={yours}` →
     `cartId={other_user's}` (cross-reference `idor-hunter`)
   - Toggle feature flags: `debug=false` → `debug=true`;
     `adminMode=false` → `true`

   Vulnerable response: The tampered field is honored server-side.

   Not-vulnerable response: Server rejects or recomputes from
   trusted backend state.

   Record: Per-field FINDING-NNN.

### Phase 5: Function-Usage Abuse

8. **One-time-function reuse** [WSTG v4.2, WSTG-BUSL-05]

   Do: For functions documented as one-per-user or one-per-session:
   - Coupon codes: redeem the same code twice
   - Free-trial: sign up for the trial with the same email /
     phone / device
   - Referral bonus: claim a referral reward twice for the same
     referrer-referee pair

   Vulnerable response: Function executes multiple times — often
   leading to direct financial impact or resource exhaustion.

   Not-vulnerable response: Second invocation rejected.

   Record: Per-function findings.

9. **Race condition on one-time functions**
   [WAHH, Ch 11]

   Do: Send 5-10 parallel requests for the SAME one-time function
   (same coupon code, same referral claim) using low-concurrency
   but simultaneous start times. Some race-prone implementations
   check the single-use flag AFTER processing, letting parallel
   requests all succeed.

   Vulnerable response: More than one parallel request succeeded.

   Not-vulnerable response: Exactly one succeeded, the rest
   rejected.

   Record: Parallelism-count where the defense still held.

### Phase 6: Trust-Boundary Pivoting

10. **Partial-auth state pivoting**
    [WAHH, Ch 21, p. 844]

    Do: Start a flow that grants partial trust (account-recovery,
    email-verification, SSO-callback, invite-link). Before
    completing it, try to use the partial-trust state to access
    full-auth resources.

    Example: Account-recovery sends an email with a "continue
    reset" link. Open the link but don't set a new password.
    Instead, try to access `/account/settings` directly — does
    the partial-recovery session grant it?

    Vulnerable response: Partial-trust state lets the user access
    full-auth scope.

    Not-vulnerable response: Full-auth endpoints require a
    completed login, not a recovery-initiated session.

    Record: Per-flow FINDING-NNN.

11. **Cross-system hand-off trust**
    [WAHH, Ch 21]

    Do: If the app has hand-off points (payment redirect from a
    third-party processor, SSO callback, webhook from an internal
    service), try to mimic the hand-off callback with tampered
    parameters.

    Example: If payment success is confirmed via a
    `/payment-callback?orderId=X&status=success` URL, try
    manually visiting the URL without actually paying.

    Vulnerable response: Order marked paid without real payment.

    Not-vulnerable response: Server validates the callback via a
    signed token or IP whitelist.

    Record: Cross-reference `ssrf-hunter` for webhook-SSRF
    variants.

## Payload Library

Categories:

- **Workflow-step jumps**: `/auth/success`, `/checkout/confirm`,
  `/step3`, `/complete`
- **Logical-invalid numerics**: `-1`, `0`, `999999999999`, `1.5`,
  unicode digits
- **State-flag flips**: `hasPaid=true`, `mfa=false`, `admin=true`,
  `approvalRequired=false`
- **Cross-currency confusion**: different `currency` codes paired
  with original `price` values
- **Parallel one-time probes**: 5-10 concurrent requests for the
  same single-use operation
- **Trust-pivot probes**: partial-auth session + direct
  full-auth URL

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-840 (Business Logic Errors). CWE-841 (Improper
  Enforcement of Behavioral Workflow) for step-skipping.
  CWE-20 (Improper Input Validation) for logical-invalid data.
  CWE-837 (Improper Enforcement of Single, Unique Action) for
  one-time-function reuse.
- **OWASP**: WSTG-BUSL-01 through WSTG-BUSL-09. For APIs,
  API6:2023 (Unrestricted Access to Sensitive Business Flows).
  A04:2021 (Insecure Design) for design-level gaps.
- **CVSS vectors**: direct financial theft —
  `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`. Step-skip bypassing
  payment — `...PR:L/C:N/I:H/A:N`. Coupon reuse at scale —
  `...AC:L/C:N/I:L/A:N` (aggregated financial impact, not per-user
  severity).
- **Evidence**: the workflow HAR (normal path), the tampered
  request, the server response, and the resulting state change
  (order with $0 total, free trial granted twice, etc.).
- **Remediation framing**: backend engineer + product. Include:
  - Server-side authoritative state (don't trust client
    `step=complete`)
  - Transactional rollback (entire workflow commits or rolls
    back atomically)
  - Input range validation (min/max per field, including
    logical constraints)
  - Canonical-value server lookup (price from product table,
    not client request)
  - Idempotency keys + DB-level unique constraints for
    one-time functions
  - HMAC-signed callback parameters for cross-system hand-offs

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every finding has a workflow HAR (happy path) + the
      tampered-request + server response
- [ ] Every financial-impact finding stopped at first confirmation
      (no "how much" escalation)
- [ ] Every persistent-record finding includes a coordinated revert
      request
- [ ] Only test accounts and test billing were used
- [ ] Race-condition tests used moderate concurrency (5-10), not
      hundreds
- [ ] Workflow documentation (if provided in `{workflow_docs}`)
      was consulted — findings reference the specific intended-
      behavior violation
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Uniform success with embedded error**: The server returns 200
  for out-of-order requests but the body contains "Please complete
  step N+1 first". Automated tools misread. Always check response
  body.

- **Client-side-only enforcement**: A GUI-level price manipulation
  appears to work in the browser, but the server bills the original
  price during final processing. Confirm with a server-side GET
  of the completed transaction.

- **Race-condition false negatives**: Single-attempt tests may
  succeed due to timing. Re-run race-condition tests 3 times; the
  bug may only manifest under specific concurrency patterns.

- **Coupon-reuse as intended behavior**: Some coupons are
  legitimately multi-use (site-wide codes, recurring subscriber
  rewards). Check product docs / admin UI before filing — the
  defect is "one-per-user" codes being reused, not all coupons.

- **Partial-trust pivot that's actually intended**: Password-reset
  flows legitimately grant a narrow session to set a new password.
  The bug is when that session also grants unrelated full-auth
  scope. Distinguish by checking what the partial session is
  authorized to do — if it's scoped to password-reset only, the
  flow is correct.

- **Negative-price that refunds to original payer, not attacker**:
  A negative-quantity bug may result in an inventory error
  (stock increments) without financial impact because the
  negative charge is refunded to the payer, not the attacker.
  Still a finding — operations risk, inventory fraud — but lower
  severity than direct theft.

## References

External:
- WSTG-BUSL family: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
- CWE-840: https://cwe.mitre.org/data/definitions/840.html
- CWE-841: https://cwe.mitre.org/data/definitions/841.html
- OWASP Logic-Flaw-testing guide:
  https://owasp.org/www-community/attacks/Business_logic_attack

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia de Vulnerabilidades em Lógica de Negócios.md`

Grounded in:
- The Web Application Hacker's Handbook, Ch 11 (Attacking
  Application Logic) + Ch 21 (Exploit Chaining)
- Hacking APIs, Ch 7 (Endpoint Analysis)
- OWASP WSTG v4.2 (Section 4.10)
- Bug Bounty Bootcamp, Ch 17-18 (Logic Bypasses)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
