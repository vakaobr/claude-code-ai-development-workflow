---
name: graphql-hunter
description: "Tests GraphQL endpoints for enabled production introspection, BOLA via guessable relay/global IDs, deeply-nested DoS, query batching bypass, injection in query arguments (SQLi / command injection through GraphQL resolvers), custom-scalar validation gaps, and field-level authorization flaws. Use when the target exposes /graphql, /graphiql, /playground, /v1/graphql, /query endpoints; or when response bodies have top-level `data` or `errors` keys; or when the orchestrator's recon confirmed GraphQL use. Produces findings with CWE-200 / CWE-639 / CWE-400 / CWE-89 mapping, introspection-driven schema evidence, and per-vector remediation. Defensive testing only, against assets listed in .claude/security-scope.yaml."
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
  source_methodology: "Guia de Segurança e Testes em APIs GraphQL.md"
  service_affecting: false
  composed_from: []
---

# GraphQL Hunter

## Goal

Test GraphQL endpoints for the unique-to-GraphQL flaws
(introspection, deeply-nested DoS, batching bypass, scalar
validation) and for the generic API flaws that manifest through
GraphQL resolvers (BOLA, SQLi, command injection, field-level
authz). This skill implements WSTG-APIT-01 for GraphQL and maps
findings to CWE-200 (info exposure via introspection), CWE-639
(BOLA), CWE-400 (resource exhaustion via nested queries), CWE-89
(SQLi through resolvers), and CWE-285 (field-level authz). The
goal is to hand the API team a concrete list of findings with
introspection-driven schema evidence and per-vector remediation
(depth limiting, cost analysis, scalar validators, field
authorization).

## When to Use

- The target exposes a GraphQL endpoint at any standard path
  (`/graphql`, `/graphiql`, `/playground`, `/v1/graphql`,
  `/api/graphql`, `/query`).
- `api-recon` confirmed GraphQL via body inspection (top-level
  `data` or `errors` keys; queries containing `query`,
  `mutation`, `subscription`).
- `Accept: application/graphql-response+json` header is seen in
  responses.
- The orchestrator detected GraphiQL / Altair / Apollo Playground
  paths.

## When NOT to Use

- For REST / JSON APIs — use `owasp-api-top10-tester`,
  `bola-bfla-hunter`, `mass-assignment-hunter`, or the specific
  class's hunter.
- For generic JSON injection — use `sqli-hunter` against
  resolver-arguments; this skill dispatches to it for the
  injection phase.
- For JWT flaws in GraphQL bearer tokens — use `jwt-hunter`; this
  skill maps the auth model, JWT specifics go to jwt-hunter.
- For GraphQL Federation or Apollo Router-specific
  misconfigurations (variant: `@federation` directive misuse) —
  file a gap in `references/gaps.md`; this skill doesn't yet
  cover federation-specific attacks.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist
   or doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND
   its `testing_level` is `active`.
3. Denial-of-service via deeply-nested queries is destructive
   against production. Confirm the asset's `destructive_testing`
   is `approved` AND `service_affecting` is `approved` before
   running Phase 5. If either is `denied`, skip the DoS test but
   note the configuration risk based on introspection (query-depth
   limit, cost-analysis enablement).
4. Injection testing (Phase 6) uses read-only SQLi / command
   injection probes; same limitations as `sqli-hunter`
   (no DROP/DELETE/UPDATE/INSERT/xp_cmdshell).
5. If the target is ambiguous, write it to
   `.claude/planning/{issue}/SCOPE_QUESTIONS.md` and halt for
   that target only.
6. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
   with status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{graphql_path}`: the GraphQL endpoint URL (from `api-recon`
  output or scope_context)
- `{user_a}`: authenticated token (typically Bearer JWT) for
  user A
- `{user_b}`: authenticated token for user B (required for BOLA)
- `{oob_listener}`: authorized OOB listener URL for blind-injection
  tests (from scope)

## Methodology

### Phase 1: Endpoint and IDE Discovery

1. **Confirm the GraphQL endpoint responds** [Hacking APIs, Ch 14, p. 286]

   Do: `curl -X POST {graphql_path} -H "Content-Type:
   application/json" -d '{"query":"{__typename}"}'`.

   Vulnerable condition: Server responds with `{"data":
   {"__typename":"Query"}}` — GraphQL is live; __typename
   was not blocked.

   Not-vulnerable condition: 404 / 403 — endpoint doesn't
   exist or blocks unauthenticated probes.

   Record: Endpoint details in `.claude/planning/{issue}/graphql-targets.md`.

2. **Probe for exposed IDEs** [WSTG v4.2, 4.12.1]

   Do: Test for developer-oriented interfaces:
   ```
   /graphiql
   /graphiql/
   /playground
   /altair
   /voyager
   /api/explorer
   /_apollo_explorer
   ```

   Vulnerable condition: An IDE is exposed in production —
   lowers the bar for attacker enumeration.

   Record: Each exposed IDE as a finding (Medium — information
   exposure; production should use a dev-gated environment).

### Phase 2: Introspection

3. **Full introspection query** [Hacking APIs, Ch 14, p. 289]

   Do: Submit the standard introspection query:
   ```graphql
   query IntrospectionQuery {
     __schema {
       queryType { name }
       mutationType { name }
       subscriptionType { name }
       types {
         name
         kind
         description
         fields {
           name
           type { name kind ofType { name kind } }
           args { name type { name kind } }
         }
         inputFields { name type { name kind } }
         interfaces { name }
         enumValues { name }
         possibleTypes { name }
       }
       directives {
         name
         locations
         args { name type { name kind } }
       }
     }
   }
   ```

   Vulnerable condition: Server returns the full schema in
   production — enables precise attack planning.

   Not-vulnerable condition: Introspection disabled (400 / 403 /
   specific error message from Apollo/Graphene about
   introspection being off).

   Record: Save the full schema to
   `.claude/planning/{issue}/graphql-targets/schema.json`.
   File a Medium finding for enabled introspection (unless the
   app is intentionally a public GraphQL API).

4. **Analyze schema for sensitive operations**
   [Hacking APIs, Ch 14, p. 292]

   Do: Parse `schema.json`. Extract:
   - All mutations (especially `delete*`, `admin*`, `*All`,
     `grant*`, `setRole`)
   - All queries returning potentially sensitive types (`User`,
     `Session`, `ApiKey`, `Secret`, `Config`)
   - All custom scalars (candidates for validation gaps)
   - Deeply-nested reference cycles (DoS candidates)

   Record: Per-schema annotations in
   `graphql-targets/schema-review.md`.

### Phase 3: BOLA via Relay / Global IDs

5. **Probe sequential / guessable IDs** [Hacking APIs, Ch 14, p. 292]

   Do: For each query that takes an `id: ID!` argument, test:
   - Sequential integer IDs (`1, 2, 3...`)
   - Known user A's resource IDs queried as user B
   - Relay-style base64 global IDs decoded, mutated, re-encoded:
     `echo "UXVlcnk6MTIz" | base64 -d` → `Query:123` → mutate to
     `Query:122` → re-encode

   Vulnerable response: User B's query for user A's resource
   returns A's data.

   Not-vulnerable response: 401/403/`null` with an error about
   authorization.

   Record: FINDING-NNN per vulnerable (query, ID) pair.

### Phase 4: Field-Level Authorization

6. **Field-level authz audit** [Hacking APIs, Ch 14]

   Do: For each query on a type with multiple fields (e.g.,
   `User` with `email`, `hashedPassword`, `role`, `mfaSecret`),
   request every field as a non-admin user.

   Vulnerable response: Sensitive fields (`hashedPassword`,
   `mfaSecret`, `apiKeys`, `internalNotes`) are returned to
   non-admins — authorization is at query level, not field level.

   Not-vulnerable response: Sensitive fields return `null` or
   are rejected with a per-field error.

   Record: Per-field findings; sensitive-field leaks are High.

### Phase 5: DoS via Deep Nesting and Batching (GATED)

7. **Depth-exhaustion probe (only if destructive approved)**
   [WSTG v4.2, 4.12.1, p. 954]

   Do: ONLY if scope approves destructive testing. Craft a query
   using a cyclic relationship from the schema (e.g., `User ->
   posts -> author -> posts -> author ...`) 10 levels deep.

   Watch response time. Start at depth 5, increment by 5 until
   either (a) response time exceeds 10s, or (b) depth 50 reached.
   STOP at first >10s response — do not deepen further.

   Vulnerable response: Server response time scales exponentially
   with depth.

   Not-vulnerable response: Server rejects with "query depth
   exceeds limit" at some small depth.

   Record: Depth-vs-response-time table; finding is Medium-High
   depending on how easy DoS is.

8. **Batching bypass probe** [WSTG v4.2, 4.12.1, p. 956]

   Do: Send an array of N identical login (or other rate-limited)
   queries in a single JSON array body:
   ```json
   [{"query":"mutation { login(u:\"a\",p:\"1\") { token } }"},
    {"query":"mutation { login(u:\"a\",p:\"2\") { token } }"},
    ...100 times]
   ```

   Vulnerable response: All 100 are executed in one HTTP request
   — rate limiting was per-HTTP-request not per-operation.

   Not-vulnerable response: Batching disabled or limited to N=5.

   Record: If batching is unlimited, cross-reference
   `rate-limit-hunter` for rate-limit impact assessment.

### Phase 6: Injection Through Resolvers

9. **SQLi through string arguments** [WSTG v4.2, 4.12.1, p. 951]

   Do: For query arguments whose schema declares `String!` and
   whose resolver likely does DB lookup (`userByName`,
   `searchPosts`), inject SQL metacharacters:
   ```graphql
   { searchPosts(q: "abc' OR '1'='1-- ") { id title } }
   ```

   Vulnerable response: Error message with SQL syntax signature,
   or response with cross-tenant data.

   Record: Delegate deep-dive to `sqli-hunter` — this skill flags
   the resolver as a candidate; sqli-hunter confirms.

10. **Command injection probe**
    [Hacking APIs, Ch 14, p. 295]

    Do: For arguments that might reach a shell call (filenames,
    URL values, hostnames), test metacharacter payloads:
    ```
    | && ; $() `` <> 
    ```

    Vulnerable response: Response time delay for sleep-based
    payloads, or OOB listener hit for curl-based payloads.

    Record: Delegate to `command-injection-hunter`.

### Phase 7: Custom Scalar Validation

11. **Custom scalar fuzz** [WSTG v4.2, 4.12.1, p. 951]

    Do: For custom scalars declared in the schema (e.g.,
    `scalar Date`, `scalar PhoneNumber`, `scalar EmailAddress`),
    test:
    - Literal values violating the scalar format (e.g., `Date`
      with `"not-a-date"`, `"9999-99-99"`, `"'OR'1"`)
    - Very large strings (1MB+ for String-based scalars)
    - Null bytes: `"abc def"`
    - Type-confused inputs (integer where string expected)

    Vulnerable response: Server accepts clearly-malformed values,
    returns 500 with stack trace, or processes the string
    downstream (confused deputy).

    Not-vulnerable response: Schema-level validation rejects with
    a clear GraphQL error.

    Record: Per-scalar validation-gap findings; Medium unless the
    downstream behavior is sensitive (then High).

## Payload Library

Full per-category payloads in `references/payloads.md`:

- **Introspection**: full `__schema` query + abbreviated variants
- **BOLA**: sequential integer probes, Relay ID
  decode/mutate/encode pipeline
- **Field-level authz**: sensitive-field name permutations
- **DoS depth**: nested cycle queries (starting depth 5)
- **DoS batching**: JSON array payloads
- **SQLi through resolvers**: GraphQL-syntax-wrapped SQLi
- **Command injection through resolvers**: metacharacter set
  with OOB exfil payloads
- **Scalar fuzz**: per-scalar malformed inputs

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md`
per the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-200 (info exposure) for introspection/IDEs.
  CWE-639 (BOLA). CWE-285 (field-level authz). CWE-400 (resource
  exhaustion) for DoS variants. CWE-89 (SQLi) and CWE-77
  (command injection) for resolver-bound injection. CWE-20 for
  scalar-validation gaps.
- **OWASP**: For APIs: API1:2023 (BOLA), API3:2023 (BOPLA for
  field-level), API4:2023 (Unrestricted Resource Consumption for
  DoS/batching), API8:2023 (Security Misconfiguration for
  introspection).
- **CVSS vectors**: BOLA on sensitive types (user PII, messages)
  — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`. Mass data disclosure
  via field-level authz gap — `...C:H/I:L/A:N`. DoS via nesting
  on prod — `...C:N/I:N/A:H`.
- **Evidence**: the exact GraphQL query + variables; the response
  body (truncated if huge); schema excerpt from introspection
  confirming the field or type involved.
- **Remediation framing**: backend engineer who owns the GraphQL
  schema. Include:
  - `graphql-depth-limit` or Apollo `maxDepth` config
  - `graphql-cost-analysis` for cost-based limiting
  - Field-level authz with resolver guards (`graphql-shield`,
    Apollo `@auth` directive, Hasura row-level permissions)
  - Custom scalar validators (`graphql-scalars` library)
  - Introspection disabling in production
    (`introspection: false` in Apollo)

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Introspection test was run and the schema saved locally
- [ ] DoS nesting test stayed within approved depth (<=50) and
      stopped at first excessive response
- [ ] No destructive mutations were fired (`delete*`, `admin*`)
      even on in-scope assets
- [ ] Batching test used harmless read queries, not mutations
- [ ] Injection findings flag for delegation to `sqli-hunter` /
      `command-injection-hunter`, don't attempt escalation here
- [ ] Field-level authz tests used non-admin session for
      requests to admin fields
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Uniform 200 OK**: Many GraphQL implementations always return
  200 with errors in the `errors` key. Automated tools reading
  the status alone misread failed probes as success. Always
  check `response.errors` and `response.data`.

- **Intentionally-public introspection**: Public GraphQL APIs
  (Shopify Storefront, GitHub V4) intentionally enable
  introspection because the whole point is developer
  accessibility. Confirm the app is public-developer-facing
  before filing as a vulnerability.

- **Deep nesting as a legitimate feature**: Some apps legitimately
  allow deep nesting for product requirements (comments within
  comments within comments). DoS is only a finding if nesting
  enables disproportionate resource consumption.

- **`null` on BOLA not always a good signal**: Some GraphQL APIs
  return `null` both for "doesn't exist" and "not authorized",
  making BOLA detection noisy. Confirm by requesting the same
  ID as user A (owner) — if A gets data, B should get `null` or
  error; if A also gets `null`, the resource just doesn't exist.

- **Cost-analysis disguised as depth limit**: Server rejects deep
  queries with "query too expensive" instead of "depth exceeded"
  — cost analysis is in place, which is stronger than simple
  depth limiting. Note the app is protected.

## References

- `references/payloads.md` — full per-category payload catalog
- `references/remediation.md` — per-library remediation snippets
  (Apollo, Graphene, graphql-ruby, Hot Chocolate)

External:
- WSTG-APIT-01: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL
- CWE-200: https://cwe.mitre.org/data/definitions/200.html
- CWE-639: https://cwe.mitre.org/data/definitions/639.html
- GraphQL Security (Hasura):
  https://hasura.io/learn/graphql/security/
- PortSwigger GraphQL labs:
  https://portswigger.net/web-security/graphql

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia de Segurança e Testes em APIs GraphQL.md`

Grounded in:
- Hacking APIs, Ch 14 (GraphQL) + Ch 15 (GraphQL case studies)
- OWASP WSTG v4.2 (Section 4.12.1)
- OWASP API Security Top 10 (API1:2023, API3:2023, API4:2023,
  API8:2023)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
