---
name: api-recon
description: "Maps the attack surface of REST / GraphQL / gRPC APIs — OSINT for specs and endpoints, subdomain enumeration, active service fingerprinting, OpenAPI / Swagger / GraphQL-schema discovery, and hidden-parameter fuzzing. Use before any API-class hunter skill (bola-bfla-hunter, mass-assignment-hunter, owasp-api-top10-tester, jwt-hunter, graphql-hunter); they depend on its API_INVENTORY.md output. Run AFTER web-recon-passive and in parallel with or after web-recon-active. Produces API_INVENTORY.md with endpoints, methods, parameters, auth models, and versioning. Defensive testing only, against assets listed in .claude/security-scope.yaml."
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
  source_methodology: "Guia de Reconhecimento e Mapeamento de Superfície de APIs.md"
  service_affecting: true
  composed_from: []
---

# API Recon

## Goal

Produce a complete API-surface inventory for in-scope targets so that
downstream API-class hunter skills (BOLA/BFLA, mass-assignment,
GraphQL, JWT, rate-limit) have a precise list of endpoints, methods,
parameters, and authentication models to work against. This skill
implements WSTG-INFO-02 + API-specific OSINT and maps to OWASP
API9:2023 (Improper Inventory Management) — inventory is the
prerequisite for every later API test. No vulnerability findings are
produced by this skill; its output is the inventory document.

## When to Use

- The target exposes REST, GraphQL, gRPC, or SOAP APIs (confirmed by
  `Content-Type: application/json|xml|grpc-web` in responses, or by
  dedicated API subdomains like `api.*`).
- Before any API-class hunter runs — these skills expect
  `API_INVENTORY.md` to exist.
- When modernizing an assessment that was last run as a web-app-only
  audit — API surface may have been added since.
- When the orchestrator identifies `api.`, `v1.`, `dev-api.`, or
  `graphql` subdomains during subdomain enumeration.

## When NOT to Use

- For server-rendered HTML applications without an API layer — use
  `web-recon-active` only.
- For internal RPC buses not reachable from the assessed
  perspective — scope-file boundary.
- For re-running on surface already mapped in the last 7 days —
  read the existing `API_INVENTORY.md` instead.
- For exploit confirmation (BOLA, BFLA, mass-assignment) — those are
  hunter skills that consume this skill's output.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or
   doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND its
   `testing_level` is `active`.
3. `service_affecting: true` — active parameter fuzzing and
   path-enumeration generate real traffic. Confirm the asset's
   `service_affecting` field is `approved`; otherwise halt and
   request approval.
4. Apply the scope file's `rate_limit_rps`. For API recon, respect
   stricter per-endpoint rate limits if the target signals them via
   `Retry-After` headers — back off immediately.
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with
   status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — known API base paths or subdomains
- `{user_a}`: optional — authenticated token/session (enables
  authenticated endpoint discovery, which typically reveals more)
- `{user_admin}`: optional — admin-tier session for admin-surface
  discovery (coordinate with `{user_a}` ownership)

## Methodology

### Phase 1: Passive OSINT for APIs

1. **GitHub / OSINT spec hunt** [Hacking APIs, Ch 6, p. 125]

   Do: Search `site:github.com "{org_name}" swagger.json`,
   `"{org_name}" openapi.yaml`, and `"{org_name}" postman`. Also
   search organizational wikis, developer portals, and hackerone
   scope pages if the program is public.

   Record: Any public spec URLs or repos in
   `.claude/planning/{issue}/api-recon/osint-sources.md`. Leaked spec
   files are gold — they enumerate every endpoint the app intends.

2. **Wayback / historical URL harvest** [Hacking APIs, Ch 6, p. 131]

   Do: `waybackurls {target} | grep -Ei '(api|graphql|v[0-9]+|swagger|openapi)' | sort -u`
   and cross-reference with `gau {target}`.

   Record: Historical API endpoints that may still be active (classic
   "forgotten v1") in `api-recon/historical-urls.txt`.

### Phase 2: Active Subdomain and Service Discovery

3. **Enumerate API subdomains** [WSTG v4.2, WSTG-INFO-02]

   Do: Subdomain enumeration focused on API-indicative prefixes:
   `amass enum -passive -d {target} | grep -Ei '^(api|v[0-9]|graphql|rest|rpc|dev-api|staging-api|internal-api|legacy-api)\.'`.
   Then `httpx -u - -status-code -content-type -tech-detect` to
   confirm liveness and content types.

   Vulnerable condition: Dev/staging/legacy API subdomains reachable
   from the public internet — Improper Asset Management.

   Record: Subdomain matrix in `API_INVENTORY.md` under "API Hosts".

4. **Non-standard-port service scan**
   [Hacking APIs, Ch 6, p. 215]

   Do: `nmap -sC -sV -Pn --script=safe -p 80,443,8080,8443,8888,3000,4000,5000,8000,9000,9200
   {target}` — APIs often run on non-standard ports.

   Vulnerable condition: APIs on 8080/8443/etc. that return JSON
   (`Content-Type: application/json`) on 401/404 — unauth APIs leaked
   through the edge.

   Record: Port/service matrix, cross-ref with web-recon-active's
   scan to avoid duplicate work.

### Phase 3: Specification and Schema Discovery

5. **Probe standard doc paths**
   [Hacking APIs, Ch 7, p. 159]

   Do: For each API host, GET:
   ```
   /swagger.json
   /swagger.yaml
   /openapi.json
   /openapi.yaml
   /v1/swagger/
   /v2/swagger/
   /v3/swagger/
   /api-docs/
   /docs/api
   /redoc
   /explorer
   /graphql
   /graphiql
   /api/v1/schema
   /.well-known/openid-configuration
   ```

   Vulnerable condition: Spec is reachable without authentication —
   the tester (and anyone else) gets a full endpoint list.

   Record: Available specs with URLs in `API_INVENTORY.md` under
   "API Specs". Download specs into
   `.claude/planning/{issue}/api-recon/specs/`.

6. **GraphQL introspection**
   [Hacking APIs, Ch 7]

   Do: If `/graphql` or `/graphiql` responds, probe introspection:
   ```bash
   curl -X POST https://{target}/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'
   ```

   Vulnerable condition: Introspection returns the full schema — every
   query, mutation, and subscription with types. Cross-reference for
   `graphql-hunter`.

   Not-vulnerable condition: Introspection disabled (400/403 or empty
   response).

   Record: Schema dump in `api-recon/specs/graphql-schema.json`.

### Phase 4: Endpoint and Parameter Enumeration

7. **Path brute-force with API wordlists**
   [Hacking APIs, Ch 6, p. 145]

   Do: `ffuf -u https://{target}/FUZZ -w {wordlist_dir}/api-endpoints.txt
   -H "Accept: application/json" -mc 200,201,401,403 -rate {rate_limit_rps}`
   using API-focused wordlists (kiterunner has the best corpus).

   Cross-reference found paths with spec-declared paths to identify
   undocumented endpoints.

   Vulnerable condition: Endpoints not in any public spec (especially
   `/internal/*`, `/admin/*`, `/debug/*`).

   Record: Path inventory in `API_INVENTORY.md` under "Endpoints".

8. **HTTP method fuzzing per endpoint**
   [Hacking APIs, Ch 7, p. 166]

   Do: For each endpoint, probe each method:
   ```bash
   for m in GET POST PUT PATCH DELETE OPTIONS; do
     curl -X $m -s -o /dev/null -w "$m %{http_code}\n" \
       "https://{target}/{endpoint}"
   done
   ```

   Vulnerable condition: Mismatches between the spec's declared methods
   and the server's accepted methods — `DELETE` accepted on a
   `GET`-only documented endpoint, or `PUT` on a list resource.

   Record: Per-endpoint method matrix in `API_INVENTORY.md` under
   "Methods".

9. **Hidden-parameter discovery**
   [Hacking APIs, Ch 11, p. 303]

   Do: For each endpoint, run `arjun -u
   "https://{target}/{endpoint}" -m GET,POST -H
   "Authorization: Bearer {user_a_token}" -t 5 --rate-limit
   {rate_limit_rps}` with API-oriented wordlists.

   Vulnerable condition: Response shape / length changes with
   previously-unknown parameter added (debug=true, admin=1,
   impersonate=X).

   Record: Hidden-param inventory in `API_INVENTORY.md` under
   "Hidden Parameters".

### Phase 5: Auth Model and Workflow Capture

10. **Auth-flow mapping** [Hacking APIs, Ch 7, p. 172]

    Do: Exercise login / token issuance / refresh flows. Capture:
    - Token format (JWT? opaque? cookie? `Authorization: Bearer` vs
      custom `X-Api-Key`)
    - Token scope encoding (claims, roles)
    - Token expiry
    - Refresh semantics (rotation? revocation?)
    - MFA steps
    - Rate-limit headers (X-RateLimit-*)

    Record: Auth model in `API_INVENTORY.md` under "Auth". Cross-reference
    with `auth-flow-mapper` for deeper auth-flow analysis and
    `jwt-hunter` if tokens are JWTs.

11. **Representative workflow trace**
    [Hacking APIs, Ch 7, p. 166]

    Do: For each major user journey (create account → create resource
    → modify → delete), record the exact request sequence (method,
    path, headers, body).

    Record: Workflow traces in `api-recon/workflows/` so downstream
    skills (especially `business-logic-hunter`) have real request
    shapes to work from.

## Payload Library

No exploit payloads — inventory only. Key probe patterns:

- **Google dorks for specs**: `site:github.com "{org}" swagger.json`
- **Subdomain patterns**: `api.`, `v1.`, `v2.`, `dev-api.`,
  `staging-api.`, `internal-api.`, `legacy-api.`, `graphql.`
- **Spec paths**: `/swagger.json`, `/openapi.json`, `/graphql`,
  `/api-docs/`, `/redoc`
- **GraphQL introspection query**: full `__schema` enumeration
- **Method fuzz set**: `GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD`
- **Hidden-param wordlists**: API-specific (arjun default + bug-bounty
  community lists)

## Output Format

This skill does NOT directly produce vulnerability findings. Its
output is **the** inventory document consumed by every API hunter:

- `.claude/planning/{issue}/API_INVENTORY.md` — the primary artifact,
  structured as:
  - **API Hosts** (subdomain matrix + liveness + tech stack)
  - **API Specs** (URL + local copy + version)
  - **Endpoints** (path + description if spec-available + tags)
  - **Methods** (per-endpoint method matrix with server vs spec delta)
  - **Parameters** (per-endpoint query/body/header params, with types)
  - **Hidden Parameters** (arjun hits not in spec)
  - **Auth** (scheme, token format, claims, refresh policy)
  - **Rate Limits** (response headers + observed throttling)
  - **Versioning** (current + legacy + deprecated endpoints still live)

When this skill DOES file a finding to SECURITY_AUDIT.md, it's for
obvious discoveries:

- **Publicly-reachable internal/legacy APIs** → API9:2023 (Improper
  Inventory Management), CWE-1059
- **Leaked API spec** → CWE-200 (Information Exposure), severity
  depends on what's in the spec
- **GraphQL introspection enabled in production** → CWE-200, severity
  High if schema contains admin mutations

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] API_INVENTORY.md has all 9 sections populated (or marked "none")
- [ ] Spec files are saved locally, not just linked (specs can be
      removed after recon)
- [ ] The scope rate limit was honored (verify via scan logs)
- [ ] Every subdomain scanned was in-scope (grep logs against scope)
- [ ] Authenticated endpoints were discovered if `{user_a}` was
      provided
- [ ] GraphQL introspection was attempted if GraphQL endpoints exist
- [ ] Hidden-param discovery ran against authenticated endpoints too
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Catch-all 200**: Many APIs return HTTP 200 for all paths with a
  `{"error": "not found"}` body. Use body-based differential matching
  (`ffuf -fs` or `-fr`) not status codes.

- **Stale Wayback entries**: Historical URLs may have been
  decommissioned. Confirm liveness before adding to the inventory.

- **Defender deception**: Orgs sometimes deploy fake `/admin` or
  `/internal` paths as honeypots. If a discovered path returns a
  login page for a CMS the rest of the app doesn't use, flag as
  probable honeypot before filing.

- **Auth header masking**: Spec files may list `Authorization: Bearer`
  but the server also accepts `X-Api-Key`. Both deserve inventory
  entries.

- **GraphQL false-off signal**: Some GraphQL implementations return 400
  on introspection but 200 on persisted/allowlisted queries —
  introspection is off, but the surface is still enumerable via other
  means (mutation-name fuzzing). Note both.

- **Rate-limit false positives in inventory**: Aggressive enumeration
  can trigger temporary bans that make the inventory look incomplete.
  If responses switch from 200 to 429 after N requests, pause, then
  resume at half the rate.

## References

External:
- WSTG-INFO-02: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server
- OWASP API9:2023: https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/
- kiterunner: https://github.com/assetnote/kiterunner
- arjun: https://github.com/s0md3v/Arjun
- amass: https://github.com/owasp-amass/amass

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia de Reconhecimento e Mapeamento de Superfície de APIs.md`

Grounded in:
- Hacking APIs, Ch 6 (Passive/Active Recon) + Ch 7 (Endpoint Analysis) +
  Ch 11 (Fuzzing)
- Bug Bounty Bootcamp, Ch 24 (API Hacking)
- OWASP WSTG v4.2 (WSTG-INFO-02, WSTG-INFO-06)
- OWASP API Security Top 10 (API9:2023)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
