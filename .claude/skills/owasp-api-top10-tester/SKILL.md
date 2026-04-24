---
name: owasp-api-top10-tester
description: "Runs a full OWASP API Security Top 10 coverage sweep against a target — dispatches to class-specific hunters (bola-bfla-hunter, auth-flaw-hunter, excessive-data-exposure-hunter, rate-limit-hunter, mass-assignment-hunter, sqli-hunter, command-injection-hunter, jwt-hunter) for each Top-10 item, then produces a consolidated API-Top-10 coverage matrix showing which items were tested, what was found, and which items need follow-up. Use as the 'API sweep' entry point when the orchestrator wants broad-but-shallow coverage, or as the pre-deploy final check. Produces .claude/planning/{issue}/API_TOP10_COVERAGE.md alongside any downstream findings. Defensive testing only, against assets listed in .claude/security-scope.yaml."
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
  subcategory: api
  authorization_required: true
  tier: T1
  source_methodology: "Guia Metodológico de Segurança em APIs OWASP.md"
  service_affecting: false
  composed_from: []
---

# OWASP API Top 10 Tester

## Goal

Perform a structured OWASP API Security Top 10 assessment by
orchestrating class-specific hunter skills for each item and
producing a single consolidated coverage matrix. This skill does
NOT re-implement each item's methodology — it dispatches to the
specialized hunter skill and aggregates results. Output maps
directly to OWASP API Top 10 categories and supports the
compliance-focused reporting that reviewers and auditors expect.
Implements WSTG-API family (meta-skill) and produces
`API_TOP10_COVERAGE.md` as its primary artifact.

## When to Use

- The target is API-first (REST / GraphQL / gRPC / SOAP) and the
  assessment needs OWASP-API-Top-10-aligned coverage.
- A compliance framework (SOC 2, ISO 27001, PCI) requires explicit
  coverage evidence per OWASP category.
- As the final "API sweep" before a major release, running in
  parallel with class-specific deep dives.
- The orchestrator wants a single entry point that guarantees
  baseline coverage without micro-managing each sub-skill.

## When NOT to Use

- For deep testing of a single class — dispatch directly to the
  class-specific hunter (faster, richer findings).
- For web-app-first assessments where the target isn't API-heavy
  — use the individual hunters; this skill's dispatching overhead
  isn't worth it for 2-3 classes.
- For non-HTTP APIs (raw TCP, binary protocols) — source
  methodology doesn't cover these; file a gap.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist
   or doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND
   its `testing_level` is `active`.
3. This skill invokes other skills via the orchestrator. Each
   dispatched skill's OWN Authorization Check still runs — this
   skill only coordinates; it does not bypass per-skill gating.
   If a dispatched skill halts (e.g., `auth-flaw-hunter` needs
   security-team notification), this skill waits and surfaces the
   halt reason in the coverage matrix.
4. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
   with status `running`. Include which Top-10 items will be
   dispatched.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — subsections of the API to focus on
- `{user_a}`: regular-user test credentials
- `{user_b}`: second regular-user test credentials (for BOLA)
- `{user_admin}`: admin credentials (for BFLA)
- `{skip_items}`: optional — list of Top-10 items to skip (e.g.,
  `[API4]` if rate-limit testing is deferred to a separate window)

## Methodology

Each phase below corresponds to one OWASP API Top 10 item
(2019 / 2023 editions — this skill honors the updated 2023
version primarily). Each dispatches to a specialized hunter skill
and records the outcome.

### Phase 1: Prerequisites

1. **Verify API inventory exists** [Hacking APIs, Ch 6]

   Do: Confirm `API_INVENTORY.md` exists for the issue. If not,
   halt and request `api-recon` run first.

   Record: Verified-present in coverage matrix.

### Phase 2: API1:2023 — Broken Object Level Authorization

2. **Dispatch to `bola-bfla-hunter` (BOLA section)**

   Do: Invoke `bola-bfla-hunter` with Phases 1-3 (object ID
   inventory, A-B token swap, side-channel enumeration).

   Record: Outcome in coverage matrix: `API1 — {finding_count}
   findings — dispatched-to: bola-bfla-hunter`.

### Phase 3: API2:2023 — Broken Authentication

3. **Dispatch to `auth-flaw-hunter` + `jwt-hunter`**

   Do: Invoke `auth-flaw-hunter` for username enumeration, lockout,
   multi-stage bypass, default credentials, and alternative-channel
   policy drift. Then invoke `jwt-hunter` if JWTs are in use.

   Record: Combined outcome, both skills' finding counts.

### Phase 4: API3:2023 — Broken Object Property Level Authorization (BOPLA)

4. **Dispatch to `excessive-data-exposure-hunter` +
   `mass-assignment-hunter`**

   Do: API3:2023 covers both READING too many properties (excessive
   exposure, legacy API3:2019) AND WRITING too many properties
   (mass assignment, legacy API6:2019). Invoke both skills.

   Record: Combined coverage.

### Phase 5: API4:2023 — Unrestricted Resource Consumption

5. **Dispatch to `rate-limit-hunter`**

   Do: Invoke for lockout / SMS-cost / payload-size / function-usage
   tests. Honor `service_affecting` gating — may halt waiting for
   scope approval; surface that as a coverage gap if so.

   Record: Outcome; "halted-awaiting-approval" is a valid state.

### Phase 6: API5:2023 — Broken Function Level Authorization

6. **Dispatch to `bola-bfla-hunter` (BFLA section)**

   Do: Invoke `bola-bfla-hunter` with Phase 3 (admin-endpoint probe
   with regular-user token, method-swap BFLA).

   Record: Outcome.

### Phase 7: API6:2023 — Unrestricted Access to Sensitive Business Flows

7. **Dispatch to `business-logic-hunter` +
   `rate-limit-hunter` (function-usage)**

   Do: Invoke `business-logic-hunter` for workflow bypass,
   one-time-function reuse. Cross-reference `rate-limit-hunter`
   Phase 4 (function-usage limits) if already run.

   Record: Combined.

### Phase 8: API7:2023 — Server-Side Request Forgery

8. **Dispatch to `ssrf-hunter`**

   Do: Invoke full `ssrf-hunter` methodology. Honor internal-IP
   gating.

   Record: Outcome; if cloud credentials were recovered, note
   the cross-skill handoff to `aws-iam-hunter`.

### Phase 9: API8:2023 — Security Misconfiguration

9. **Synthesize misconfiguration findings**

   Do: This item doesn't have a single dedicated hunter — it
   aggregates from:
   - `crypto-flaw-hunter` for TLS / HSTS / cookie-flag issues
   - `web-recon-active` / `api-recon` findings for verbose errors,
     exposed admin paths, CORS misconfigurations
   - `cors-misconfig-hunter` for CORS specifically (if run)
   - Missing security headers via a direct `WebFetch` audit
     (X-Content-Type-Options, X-Frame-Options — cross-reference
     `clickjacking-hunter` for frame-ancestors)

   Do: Run a consolidated check:
   ```bash
   curl -sI https://{target}/ | grep -iE "content-security-policy|strict-transport-security|x-content-type-options|x-frame-options|referrer-policy|permissions-policy"
   ```

   Record: Per-header matrix. File Medium findings for each
   missing header appropriate to the asset type.

### Phase 10: API9:2023 — Improper Inventory Management

10. **Inventory-drift check**

    Do: From `api-recon`'s `API_INVENTORY.md` extract:
    - `/v1/`, `/v2/`, `/beta/` endpoints still live alongside
      current versions
    - `dev-api.`, `staging-api.`, `legacy-api.` subdomains
      reachable from the public internet
    - Undocumented endpoints surfaced by path brute-force (not in
      public spec)
    - Deprecation headers absent on legacy endpoints

    Vulnerable: any of the above.

    Record: Per-drift finding. Severity typically Medium, elevated
    if the legacy endpoint bypasses modern auth or exposes
    decommissioned functionality.

### Phase 11: API10:2023 — Unsafe Consumption of APIs

11. **Third-party API consumption audit**

    Do: From code review (if available) or observed HTTP traffic,
    identify:
    - Third-party APIs the app calls with user-supplied parameters
      (webhook URLs, IdP endpoints, CDN URLs)
    - Trust-level assumptions (does the app blindly forward
      responses to the user? Does it accept third-party data as
      authoritative?)

    This is adjacent to SSRF (API7:2023) but specifically about
    TRUSTING third-party responses rather than SERVING to them.

    Do: For each third-party consumption, check:
    - Input validation on the third-party URL (can user pick any
      URL?)
    - Output validation on the third-party response (is the
      response sanitized before re-serving to the user?)
    - Failure-mode behavior (does an error from the third-party
      leak internal state?)

    Vulnerable response: Third-party response is returned to the
    user with minimal sanitization; third-party error reveals
    internal state; user can influence which third-party is called.

    Record: Per-consumption findings.

### Phase 12: Coverage Matrix Synthesis

12. **Produce API_TOP10_COVERAGE.md**

    Do: Write the coverage matrix to
    `.claude/planning/{issue}/API_TOP10_COVERAGE.md`:

    ```markdown
    # API Top 10 Coverage — {issue} — {target}

    | # | Category                                           | Dispatched Skill(s)        | Findings | Status |
    |---|----------------------------------------------------|----------------------------|----------|--------|
    | API1 | Broken Object Level Authorization               | bola-bfla-hunter (BOLA)    | 3        | Tested |
    | API2 | Broken Authentication                           | auth-flaw + jwt-hunter     | 2        | Tested |
    | API3 | Broken Object Property Level Authorization      | excessive-data + mass-assign | 5      | Tested |
    | API4 | Unrestricted Resource Consumption               | rate-limit-hunter          | 1        | Tested |
    | API5 | Broken Function Level Authorization             | bola-bfla-hunter (BFLA)    | 1        | Tested |
    | API6 | Unrestricted Access to Sensitive Business Flows | business-logic + rate-limit| 2        | Tested |
    | API7 | Server-Side Request Forgery                     | ssrf-hunter                | 0        | Tested |
    | API8 | Security Misconfiguration                       | crypto-flaw + header-audit | 4        | Tested |
    | API9 | Improper Inventory Management                   | api-recon + this skill     | 2        | Tested |
    | API10 | Unsafe Consumption of APIs                     | this skill                 | 0        | Tested |
    ```

    Include per-category summary paragraphs with the highest-
    severity finding per category and recommended next action.

## Payload Library

No payloads — this is a dispatching meta-skill. Specific payloads
live in each dispatched hunter. The OWASP polyglot probes from
the source note are a subset of what dedicated hunters carry:
BOLA IDs, Mass Assignment `admin:true`, JWT `alg:none`, Injection
polyglot, Rate-limit oversized-integer.

## Output Format

Findings are filed by the DISPATCHED skills, not directly by this
one. This skill's direct output is the coverage matrix.

Cross-skill aggregation into SECURITY_AUDIT.md happens through
normal per-skill appending. This skill adds a single
"API_TOP10_SUMMARY" section near the top of SECURITY_AUDIT.md
with counts and status per category.

- **Matrix**: `.claude/planning/{issue}/API_TOP10_COVERAGE.md`
- **Summary entry in SECURITY_AUDIT.md** linking the matrix and
  per-category highlights.

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] All 10 OWASP API categories have a status (Tested /
      Halted-awaiting-approval / N/A-stack-doesn't-have-this)
- [ ] Every "Tested" category cites the dispatched skill(s) and
      finding count
- [ ] Every "Halted" category records the reason (e.g.,
      "service_affecting: denied" for API4)
- [ ] The matrix in API_TOP10_COVERAGE.md matches the counts in
      SECURITY_AUDIT.md
- [ ] API9 inventory-drift check covered all subdomains from
      `api-recon`
- [ ] API10 third-party-consumption check was attempted (may be
      marked "no third-party consumption observed")
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Dispatch-without-completion**: A sub-skill starts but halts
  for approval. Mark as "halted-awaiting-approval" in the matrix;
  this is a legitimate coverage gap, not a failure.

- **Double counting when one flaw maps to multiple categories**:
  A missing authorization middleware can cause BOTH BOLA and
  BFLA. File the finding once (under the most specific category)
  and cross-reference in the other cell's "Notes".

- **API10 "no third-party" false negative**: The app may have
  third-party consumption that wasn't visible in traffic
  (server-to-server webhook registration, async queue
  processing). If code review wasn't performed, note "observable
  traffic only" in the API10 cell.

- **Skipped categories masquerading as "clean"**: If `{skip_items}`
  excluded a category, the matrix must say "Skipped" not
  "Tested — 0 findings". Auditors care about the distinction.

- **API8 "Security Misconfiguration" scope creep**: This category
  is broad — nearly any posture issue fits. Limit to what the
  dispatched skills actually tested to avoid overclaiming
  coverage.

## References

External:
- OWASP API Security Top 10 (2023): https://owasp.org/API-Security/editions/2023/en/0x00-header/
- OWASP API Security Top 10 (2019): https://owasp.org/API-Security/editions/2019/en/0x00-header/
- CWE mapping reference:
  https://cwe.mitre.org/data/definitions/1345.html (API-focused)

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia Metodológico de Segurança em APIs OWASP.md`

Grounded in:
- OWASP API Security Top 10 (2019 + 2023 editions)
- Hacking APIs, Appendix A (API Testing Checklist)
- OWASP WSTG v4.2 (API sections)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
