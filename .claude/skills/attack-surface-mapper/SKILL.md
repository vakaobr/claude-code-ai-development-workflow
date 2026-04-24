---
name: attack-surface-mapper
description: "Consolidates outputs from web-recon-passive, web-recon-active, and api-recon into a single prioritized attack-surface picture — merging PASSIVE_RECON.md, ATTACK_SURFACE.md, API_INVENTORY.md, and AUTH_FLOWS.md into a deduplicated inventory ranked by risk (high-impact features, new/changed code, legacy /v1 endpoints, business-logic-rich flows). Use at the end of the recon phase to produce a single decision document that the orchestrator uses to select which class-specific hunters to run in what order. Passive-active hybrid — mostly reads prior outputs, adds minimal targeted probes for priority fingerprinting. Produces CONSOLIDATED_ATTACK_SURFACE.md with prioritization rationale. Defensive testing only."
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
  subcategory: recon
  authorization_required: true
  tier: T4
  source_methodology: "Metodologia de Reconhecimento e Mapeamento de Superfície de Ataque.md"
  service_affecting: false
  composed_from: []
---

# Attack Surface Mapper

## Goal

Take the outputs of the three foundational recon skills
(`web-recon-passive`, `web-recon-active`, `api-recon`) plus
`auth-flow-mapper` and produce a single consolidated,
deduplicated, and PRIORITIZED attack-surface view. The
orchestrator uses this document to select which class-specific
hunters to run in what order. This skill does NOT re-run recon —
it reads what the foundational skills already produced, identifies
gaps, adds a small number of targeted probes where priorities
depend on fingerprinting, and produces
`CONSOLIDATED_ATTACK_SURFACE.md`. Maps loosely to OWASP
WSTG-INFO family as a capstone. Primary output is the
prioritization decision document.

## When to Use

- After ALL THREE recon skills have run (`web-recon-passive` +
  `web-recon-active` + `api-recon`) AND `auth-flow-mapper` has
  produced AUTH_FLOWS.md.
- As the final recon-phase step before hunter-class skills run.
- When the orchestrator needs a risk-ranked list to choose
  skill-execution order (e.g., "run auth-flaw-hunter first
  because legacy /v1/auth is the highest-risk asset").
- Mid-assessment when a major new surface has been discovered
  and the plan needs updating.

## When NOT to Use

- Before the three foundational recon skills have run — this
  skill has nothing to consolidate.
- For deep surface discovery on a single asset — use the
  specific recon skill.
- For active vulnerability testing — that's the class-specific
  hunters.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist
   or doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND
   its `testing_level` is `active`.
3. Most of this skill's work is reading prior skill outputs.
   Any targeted probes (typically <20 requests for tech-stack
   fingerprinting or version fuzzing) honor the scope's
   rate-limit. This skill should never need to issue more than
   ~50 HTTP requests.
4. If the prior-skill outputs are missing or stale (>7 days
   old), halt and recommend re-running the foundational recon
   skills first.
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
   with status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{recon_inputs}`: paths to the four prior outputs
  - `PASSIVE_RECON.md`
  - `ATTACK_SURFACE.md`
  - `API_INVENTORY.md`
  - `AUTH_FLOWS.md`

## Methodology

### Phase 1: Ingest and Deduplicate

1. **Read all four prior outputs**
   [Hacking APIs, Ch 6]

   Do: Parse each input into an intermediate Python / jq / awk
   structure. Extract:
   - Subdomains (from PASSIVE + ATTACK_SURFACE)
   - Endpoints (from all four — deduplicate)
   - Parameters (from ATTACK_SURFACE + API_INVENTORY)
   - Auth endpoints (from AUTH_FLOWS)
   - Tech stack fingerprint (from ATTACK_SURFACE + PASSIVE)
   - Open findings already filed

   Record: Raw deduplicated inventory in
   `.claude/planning/{issue}/consolidated-raw.json`.

2. **Cross-reference canonical entities** [this skill's logic]

   Do: Each asset may appear in multiple input files with
   different detail levels. Merge:
   - Subdomain entries → one canonical record per subdomain with
     (liveness, tech stack, auth required?, is-api?)
   - Endpoint entries → one canonical record per
     (method, path) with (params, auth model, inventory source)
   - Parameter entries → one per (endpoint, param) with
     (type, location, hidden?)

   Record: Normalized model.

### Phase 2: Gap Detection

3. **Inventory gaps between recon outputs**
   [Bug Bounty Bootcamp, Ch 5]

   Do: Identify surface that appears in ONE source but not
   others (usually a miss, sometimes a legitimate distinction):
   - Subdomain in CT logs but not in
     `web-recon-active`'s scan → was it reachable?
   - Endpoint in Wayback Machine but not in live spider →
     decommissioned or hidden-but-live?
   - API spec endpoint not covered by `api-recon`'s
     HTTP-method fuzz → gap worth filling

   Where ambiguous, issue a small number of targeted probes
   (`curl -sI {subdomain}` for liveness,
   `curl -sI {endpoint}` for status) — cap total at ~20 probes
   to respect rate limits.

   Record: Gap list + probe results.

### Phase 3: Risk Classification

4. **High-impact-functionality tagging**
   [zseanos methodology]

   Do: Tag each endpoint with impact-class indicators:
   - **P1-critical**: payment, auth, password reset, admin
     function, API-key management, MFA setup
   - **P2-high**: profile update (PII-bearing), document /
     message access, multi-tenant data fetch
   - **P3-medium**: search, display-only data, non-sensitive
     updates
   - **P4-informational**: static content, public info, public
     API keys (Stripe publishable, etc.)

   Use endpoint names, auth requirements, and response-shape
   hints (from API_INVENTORY) to classify. When unsure,
   classify one level higher rather than lower (err on side of
   caution).

   Record: Impact tier per endpoint.

5. **Change-recency tagging** [zseanos methodology]

   Do: Mark endpoints as "new / recently-changed" based on
   signals:
   - Wayback Machine entries absent (endpoint is recent)
   - `v2` / `v3` endpoint paths (new surface relative to older
     `v1`)
   - Git commit dates from public repos (if accessible via
     `secrets-in-code-hunter` output)
   - Recently-added CT-log certs for new subdomains

   New code is under-tested and higher-risk. Tag with
   `recently_changed: true`.

6. **Legacy / deprecated endpoint tagging**
   [Bug Bounty Playbook V2]

   Do: Tag endpoints that appear abandoned or deprecated:
   - `/v1/` when `/v2/` is the current production version
   - `legacy-*.{target}` subdomains
   - Endpoints absent from the current OpenAPI spec but still
     responding to requests
   - Endpoints that lack modern headers (no HSTS, no CSP, no
     rate-limit headers)

   Tag with `legacy: true` — these are highest-yield per effort.

7. **Business-logic-rich flow tagging**
   [Bug Bounty Bootcamp, Ch 5]

   Do: Tag multi-step flows identified in AUTH_FLOWS or from
   observation:
   - Checkout / payment
   - Account recovery
   - Approval chains
   - Subscription / plan changes
   - Multi-party transactions

   Tag with `business_logic: true` — these are candidates for
   `business-logic-hunter`.

### Phase 4: Prioritized Inventory

8. **Produce ranked hit list** [WSTG Risk Model]

   Do: Combine impact-class + change-recency + legacy + business-
   logic tags into a composite priority score:
   ```
   priority =
     impact_weight (P1=4, P2=3, P3=2, P4=1)
     + recently_changed (2)
     + legacy (3)
     + business_logic (2)
     + auth_required (1)
   ```

   Sort descending. The top entries are where orchestrator-
   selected hunter skills go first.

   Record: Ranked inventory in
   `.claude/planning/{issue}/consolidated-ranked.md`.

### Phase 5: Skill-Dispatch Recommendations

9. **Map inventory to hunter skills**
   [this skill's orchestration logic]

   Do: For each priority group, recommend which skills should
   run:
   - P1 endpoints with object-ID params → `bola-bfla-hunter`,
     `idor-hunter`
   - P1 auth endpoints → `auth-flaw-hunter`, `jwt-hunter`,
     `session-flaw-hunter`, `oauth-oidc-hunter`
   - P1 payment/workflow → `business-logic-hunter`,
     `rate-limit-hunter` (SMS/financial cost)
   - P1 URL-fetch features → `ssrf-hunter`, then
     `ssrf-cloud-metadata-hunter` if SSRF confirmed
   - P1 write endpoints with JSON bodies →
     `mass-assignment-hunter`, `sqli-hunter`,
     `excessive-data-exposure-hunter`
   - Reflective endpoints → `xss-hunter`, `dom-xss-hunter`,
     `ssti-hunter`
   - XML-accepting endpoints → `xxe-hunter`
   - Legacy `/v1/` → extra scrutiny across ALL classes
   - DNS-layer (dangling subdomains) →
     `subdomain-takeover-hunter`
   - CI/CD-infrastructure surface → `gitlab-cicd-hunter`,
     `secrets-in-code-hunter`, `aws-iam-hunter`,
     `container-hunter`
   - CORS-header-reflecting → `cors-misconfig-hunter`
   - CDN-fronted static → `cache-smuggling-hunter` (staging
     only)

   Record: Skill-dispatch plan per priority group.

### Phase 6: Synthesize CONSOLIDATED_ATTACK_SURFACE.md

10. **Write the decision document**
    [Deliverable]

    Do: Produce
    `.claude/planning/{issue}/CONSOLIDATED_ATTACK_SURFACE.md`:

    ```markdown
    # Consolidated Attack Surface — {issue} — {target}

    ## Executive Summary
    - Total subdomains: N (live / dangling / legacy breakdown)
    - Total endpoints: N (authenticated / public / deprecated)
    - Total parameters: N (hidden-discovered / documented)
    - Highest-priority class: {class}
    - Recommended first 5 skills: {list}

    ## Priority Targets (ranked)
    | # | Endpoint | Method | Auth | Impact | Recent | Legacy | BL | Priority | Recommended Skills |
    |---|----------|--------|------|--------|--------|--------|----|----------|--------------------|
    | 1 | /v1/admin/users/{id} | DELETE | admin | P1 | - | ✓ | - | 10 | bola-bfla-hunter, auth-flaw-hunter |
    | 2 | /api/v2/checkout | POST | user | P1 | ✓ | - | ✓ | 10 | business-logic-hunter, mass-assignment-hunter |
    ...

    ## Gaps in Recon
    - {list of items flagged in Phase 2 that need follow-up}

    ## Hunter Skill Dispatch Plan
    Grouped by priority:

    ### P1 (critical — run first)
    1. `auth-flaw-hunter` on /v1/auth/* (legacy auth + change
       recency)
    2. `bola-bfla-hunter` on /api/v2/accounts/{id}
    ...

    ### P2 (high — run second)
    ...

    ## Class Coverage Matrix
    (Which skills to run to cover which OWASP categories)
    ```

11. **Status + handoff**
    [Orchestrator handoff]

    Do: Update `STATUS.md`:
    - Mark recon phase COMPLETE
    - List the top 5 recommended skills with reasoning
    - Note any scope questions that surfaced during
      consolidation

## Payload Library

No new payloads — consumes and prioritizes prior outputs. Any
new probes are single `curl -sI` liveness checks capped at ~20.

## Output Format

This skill's primary output is
`CONSOLIDATED_ATTACK_SURFACE.md`. It files FINDINGS only for
recon-level issues not already filed by the upstream skills:

- **Legacy endpoints reachable alongside modern ones** →
  CWE-1059 (Incomplete Retirement of Resources),
  API9:2023 (Improper Inventory Management)
- **Undocumented-but-live endpoints** (found in live spider,
  not in spec) — typically Medium — cross-reference the class-
  specific hunter once assigned.

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — marks recon complete
  + ranked dispatch plan
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
- `.claude/planning/{issue}/CONSOLIDATED_ATTACK_SURFACE.md` —
  the primary artifact

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] All four recon inputs were read and merged
- [ ] Deduplication removed no genuinely-distinct entities
- [ ] Every endpoint has all four priority tags (impact,
      recency, legacy, business-logic)
- [ ] Top 10 ranked entries have skill-dispatch recommendations
- [ ] Gap-detection probes stayed under ~20 total requests
- [ ] Recommended skill-execution order considers both priority
      AND skill dependencies (e.g., `ssrf-hunter` must run
      before `ssrf-cloud-metadata-hunter`)
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Stale recon inputs**: Inputs older than 7 days may miss
  recent surface changes. Halt and request re-run if any input
  is stale.

- **Conflicting reports**: Two recon skills report different
  HTTP method support for the same endpoint. Usually the
  authenticated scan was more thorough — prefer
  `api-recon` output over `web-recon-active` for API endpoints;
  prefer authenticated captures over unauthenticated.

- **Prioritization arbitrariness**: The composite score is a
  heuristic, not a rule. Document the reasoning per top-10
  entry so reviewers can sanity-check — especially when a
  low-impact-class endpoint ranks high due to legacy + recent
  tags.

- **Inventory explosion for large apps**: Some targets have
  thousands of endpoints. Consolidation should collapse similar
  endpoints into patterns (e.g., `/api/v2/users/{id}/*` → one
  entry with a note on the N specific operations under it)
  rather than flat-listing every variant.

- **Authenticated-only missing from public spec**: The OpenAPI
  spec describes only public surface; the authenticated-only
  endpoints are found in live traffic. Consolidated inventory
  should mark spec-source vs live-source for each entry.

## References

External:
- OWASP WSTG v4.2 (Information Gathering phases)
- OWASP API9:2023 — Improper Inventory Management:
  https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Metodologia de Reconhecimento e Mapeamento de Superfície de Ataque.md`

Grounded in:
- Bug Bounty Bootcamp, Ch 5 + Ch 24 + Ch 25
- Hacking APIs, Ch 6 + Ch 7
- zseano's methodology (prioritization heuristics)
- Bug Bounty Playbook V2 (1-Day / legacy focus)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
