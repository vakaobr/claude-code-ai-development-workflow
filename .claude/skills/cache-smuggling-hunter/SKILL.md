---
name: cache-smuggling-hunter
description: "Tests web caches for poisoning (unkeyed-header injection turning a benign header into cached malicious content for all visitors) and HTTP request smuggling (CL.TE / TE.CL desync between front-end proxy and back-end origin, smuggling a hidden request). Highly disruptive — only runs on staging with explicit `service_affecting: approved` AND `cache_smuggling_testing: approved`. Use when the target sits behind a CDN / load balancer, X-Cache / Age / CF-Cache-Status headers are present, or when the orchestrator identifies proxied architecture. Produces findings with CWE-444 / CWE-524 mapping and header-cache-key + HTTP/2 + strict-parsing remediation. Defensive testing only — POISONED-CACHE CLEANUP REQUIRED."
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
  subcategory: server-side
  authorization_required: true
  tier: T2
  source_methodology: "Guia Técnico_ Web Cache Poisoning e HTTP Smuggling.md"
  service_affecting: true
  composed_from: []
---

# Cache Smuggling / Poisoning Hunter

## Goal

Test the target's caching layer + front-to-back HTTP parsing for
two classes of high-severity flaws:

1. **Web Cache Poisoning** — an attacker sends a request with an
   unkeyed header (e.g., `X-Forwarded-Host: attacker`) that
   influences the response. The cache stores the poisoned
   response keyed on just the URL and serves it to unwitting
   visitors. Classic XSS-for-everyone scenario.

2. **HTTP Request Smuggling** — the front-end proxy and the
   back-end origin disagree on where one HTTP request ends and
   the next begins (usually because of mismatched
   `Content-Length` vs `Transfer-Encoding: chunked` handling).
   An attacker can "smuggle" a hidden request in the request
   stream, bypassing front-end filters or hijacking responses
   meant for other users.

This skill implements WSTG-INPV-15 and WSTG-INPV-17 and maps
findings to CWE-444 (HTTP Request / Response Smuggling) and
CWE-524 (Information Exposure Through Caching). Goal: hand the
CDN / platform team a concrete list with request traces +
header-cache-key + HTTP/2 + strict-parsing remediation.

## When to Use

- The target is behind a CDN (Cloudflare, Akamai, Fastly,
  CloudFront) or load balancer (response headers include
  `X-Cache`, `Age`, `CF-Cache-Status`, `X-Served-By`).
- Custom headers (`X-Forwarded-Host`, `X-Original-URL`,
  `X-Rewrite-URL`) appear influential (cross-reference
  `web-recon-active`).
- Content-Length + Transfer-Encoding inconsistency is a risk
  (most multi-layer deployments).
- The target is a STAGING environment with explicit
  `cache_smuggling_testing: approved` in scope.

## When NOT to Use

- For non-cached, single-layer applications — no cache to
  poison.
- For production environments — smuggling probes are
  destructive. ONLY test on staging unless the scope file
  explicitly permits production (rare, requires dedicated
  incident-response coordination).
- For generic CDN misconfig (missing HSTS, wrong cache-control)
  — use `crypto-flaw-hunter` for TLS/HSTS and
  `excessive-data-exposure-hunter` for accidentally-cached
  sensitive data.
- For client-side cache issues (browser cache of sensitive
  data) — use `session-flaw-hunter`.
- Any asset not listed in `.claude/security-scope.yaml`, not in
  staging, or missing the extra gating.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist
   or doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND
   its `environment` is `staging` or `development` (NEVER
   `production` without explicit override).
3. Confirm the scope file has BOTH:
   - `service_affecting: approved`
   - `cache_smuggling_testing: approved`
   If either is absent, halt and request before running any
   probe.
4. Cache-poisoning probes pollute the cache for all users behind
   the same edge node. Plan cleanup:
   - Send a CLEAN request after every probe to overwrite the
     poisoned cache entry
   - Use cache-busting query params (`?_=<timestamp>`) during
     discovery to avoid inter-user contamination
   - Coordinate with platform team BEFORE testing — they may
     need to purge the cache manually if cleanup fails
5. Request-smuggling probes may cause transient 400/500 errors
   for other users during the test window. Same pre-test
   notification requirement as lockout testing.
6. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
   with status `running`. Include platform-team contact and
   cleanup plan.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier (staging host)
- `{scope_context}`: optional — specific paths to probe
- `{cdn_provider}`: Cloudflare / Akamai / Fastly / CloudFront /
  nginx / other (informs cleanup + probe variants)
- `{platform_contact}`: the platform engineer to notify before
  testing

## Methodology

### Phase 1: Cache-Layer Fingerprinting

1. **Identify cache presence** [Bug Bounty Playbook V2, p. 186]

   Do: Fetch a static asset multiple times and inspect headers:
   ```
   X-Cache: HIT / MISS
   Age: {seconds}
   CF-Cache-Status: HIT / MISS (Cloudflare)
   X-Served-By: {edge-id}
   X-Cache-Hits: N
   ```

   Record: `.claude/planning/{issue}/cache-smuggling-baseline.md`
   with cache-provider + behavior.

2. **Map cache key observationally**
   [Bug Bounty Playbook V2, p. 126]

   Do: Send requests varying common headers one at a time
   (`User-Agent`, `Accept-Encoding`, `Accept-Language`,
   `Cookie`, `Host`, `X-Forwarded-Host`) and observe whether the
   response changes AND whether the cache status flips MISS→HIT
   with the same URL.

   Vulnerable signal: A header influences the response but
   DOESN'T influence the cache key — that's the unkeyed-input
   primitive for poisoning.

   Record: Per-header cache-key participation matrix.

### Phase 2: Unkeyed-Header Poisoning

3. **X-Forwarded-Host poisoning probe**
   [Bug Bounty Playbook V2, p. 189]

   Do: Request a candidate page with:
   ```
   GET /?_cb={timestamp} HTTP/1.1
   Host: {target}
   X-Forwarded-Host: {oauth_callback_host}
   ```

   (Note the cache-busting `_cb` param — prevents accidental
   cross-user contamination during discovery.)

   Observe the response. If the page contains a `<script
   src="...">` or `<link href="...">` that now points to
   `{oauth_callback_host}`, the header poisoned the response.

   Vulnerable signal: Attacker-controlled host appears in
   reflected assets AND the response is cacheable.

4. **Cache persistence confirmation (CAREFUL)**
   [Bug Bounty Playbook V2, p. 127]

   Do: ONLY after Phase 1 cache-key mapping confirmed the
   header is unkeyed AND cleanup is ready:

   Step 1: Send the poisoning request WITHOUT the cache-buster
   query param (so it hits the shared cache).
   Step 2: Within 5 seconds, send a CLEAN request for the same
   URL from a different tester IP (if available).
   Step 3: Verify whether the second request receives the
   poisoned response.

   **Immediately after confirmation (within seconds, not
   minutes):**
   - Send a cleanup request to overwrite the cache
   - If overwrite doesn't work, notify platform team to PURGE

   Vulnerable signal: Second tester receives poisoned response.

   Record: FINDING-NNN Critical. Include exact time window of
   poisoning, cleanup action, verification that cache is clean.

### Phase 3: CRLF / Header Injection

5. **Header-splitting probe** [WSTG v4.2, WSTG-INPV-15]

   Do: For parameters reflected in response headers (typically
   `Location` header after a redirect), inject CRLF:
   ```
   ?redirect=https://legit%0d%0aX-Injected:+poisoned
   ```

   Vulnerable signal: Response contains the injected header
   (`X-Injected: poisoned`). Can be escalated to full response
   splitting if CRLF + body is injectable.

### Phase 4: HTTP Request Smuggling (HIGH CAUTION)

6. **CL.TE detection (safe probe)**
   [WSTG v4.2, WSTG-INPV-15]

   Do: Send a request with BOTH `Content-Length` and
   `Transfer-Encoding: chunked` where the front end honors CL
   and the back end honors TE:
   ```
   POST / HTTP/1.1
   Host: {target}
   Content-Length: 4
   Transfer-Encoding: chunked

   1
   Z
   Q
   ```

   Use a safe probe body that would produce a 400 if smuggling
   worked — not an attack payload.

   Vulnerable signal: Response behavior indicates desync
   (e.g., timeout on a subsequent request; unexpected
   status on the smuggled fragment).

   **If confirmed: STOP.** Do not craft attack payloads. File
   the finding as "desynchronization confirmed via safe probe"
   and coordinate with platform for a dedicated incident
   session to fully characterize.

7. **TE.CL detection (safe probe)**
   [WSTG v4.2, WSTG-INPV-15]

   Do: Inverse variant — front end honors TE, back end honors
   CL:
   ```
   POST / HTTP/1.1
   Host: {target}
   Content-Length: 3
   Transfer-Encoding: chunked

   8
   SAFEPROBE
   0

   ```

   Vulnerable signal: Same as above.

8. **TE.TE-variants** [Bug Bounty Playbook V2]

   Do: Test parsing-obfuscation variants:
   ```
   Transfer-Encoding: xchunked
   Transfer-Encoding : chunked
   Transfer-Encoding: chunked\nX-Foo: bar
   Transfer-Encoding:chunked
   ```

   Different proxies handle these inconsistently. A TE.TE desync
   is exploitable when one proxy honors one variant and the
   other honors the other.

   Vulnerable signal: Detected desync with a specific variant.

   **Same STOP rule.** Confirm the primitive, don't escalate.

### Phase 5: HTTP/2 Smuggling (Modern)

9. **HTTP/2 → HTTP/1.1 downgrade smuggling**
   [Bug Bounty Playbook V2]

   Do: If the target speaks HTTP/2 at the edge but downgrades to
   HTTP/1.1 at the origin (common pattern), test for
   header-injection through HTTP/2 request fields that
   downgrade incorrectly:
   ```
   :method: POST
   :path: /
   :authority: {target}
   content-length: 0
   transfer-encoding: chunked   <- HTTP/2 doesn't allow this
   ```

   Vulnerable signal: Edge accepts the HTTP/2 request but the
   downgrade emits an HTTP/1.1 request with conflicting headers
   — classic desync primitive.

### Phase 6: Cleanup Verification (MANDATORY)

10. **Post-test cache purge verification**
    [Platform hygiene]

    Do: For every cache-poisoning probe in Phase 2:
    - Send a clean request from the tester's normal IP
    - Check `X-Cache` / `CF-Cache-Status`
    - If MISS, the cache accepted the clean version (good)
    - If HIT with stale poisoned content, request platform
      team purge

    For every smuggling probe in Phase 4-5:
    - Verify the next N=10 clean requests behave normally (no
      lingering desync)
    - If any show anomalies, coordinate with platform team

    Record: Cleanup verification per finding. A finding is not
    "closed" until cleanup is verified.

## Payload Library

Full in `references/payloads.md`. Categories:

- **Unkeyed header probes**: `X-Forwarded-Host`, `X-Forwarded-For`,
  `X-Host`, `X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override`
- **Cache-buster patterns**: query-param timestamps for
  discovery-only
- **CRLF injection**: `%0d%0a`, `%250d%250a`, raw \r\n
- **CL.TE smuggling**: templates with safe smuggled fragments
- **TE.CL smuggling**: inverse
- **TE.TE obfuscation**: header-value variants
- **HTTP/2 downgrade**: `:method` + transfer-encoding patterns

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-444 (Request/Response Smuggling). CWE-524
  (Information Exposure Through Caching). CWE-93 for CRLF
  injection.
- **OWASP**: WSTG-INPV-15 (HTTP Splitting). WSTG-INPV-17 (HTTP
  Smuggling). A05:2021 (Security Misconfiguration) at the CDN
  layer.
- **CVSS vectors**: widespread cache poisoning delivering XSS —
  `AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N`. Request smuggling
  bypassing front-end auth — `...AC:H/PR:N/.../C:H/I:H/A:H`.
  CRLF injection without exploit chain — `...AC:L/C:L/I:L/A:N`.
- **Evidence**: the raw HTTP request (exact bytes, including
  CRLF), the response with cache-hit/cache-miss indicator, the
  observed desync behavior, and the cleanup verification.
- **Remediation framing**: platform / CDN engineer. Include:
  - Add problematic headers to the cache key
    (Cloudflare: Cache Key Workers; nginx: `proxy_cache_key`
    including the header)
  - Disable or strictly normalize unkeyed headers at edge
  - Enforce strict HTTP parsing: reject conflicting
    Content-Length + Transfer-Encoding at front-end
  - Use HTTP/2 end-to-end (edge and origin) to eliminate
    downgrade ambiguities
  - Disable HTTP request pipelining if not required
  - Set `Cache-Control: private` or `no-store` for
    authenticated responses

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every probe used cache-buster params during discovery (to
      avoid cross-user contamination)
- [ ] Every cache-poisoning finding has cleanup verification
- [ ] Every smuggling detection used SAFE probes (not
      attack payloads)
- [ ] Platform team was notified BEFORE Phase 4 smuggling probes
- [ ] No production environment was tested without explicit
      override
- [ ] Post-test cache purge was requested and confirmed where
      needed
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Local browser cache**: The tester's browser shows the
  poisoned response, but the server-side cache is clean. Not a
  shared-cache finding. Verify using a different browser or
  `curl` (which doesn't use the browser's cache).

- **WAF interference**: A WAF blocks the smuggling probe with
  403, but the underlying architecture might be safe OR
  vulnerable — can't tell externally. Confirm with scope-approved
  internal-network probe if available.

- **Dynamic-content reflection without cache**: The header-
  reflected response isn't cached (Cache-Control: no-store).
  Reflection alone is a weak finding — confirm the cache
  actually stores the poisoned response (X-Cache: MISS followed
  by HIT from a different requester).

- **Spurious desync signals**: High concurrency or coincidental
  backend errors can look like smuggling. Re-run smuggling
  probes 3 times at different times of day; genuine desync is
  reproducible.

- **CDN-level smuggling protection**: Modern Cloudflare / Akamai
  normalize headers at the edge and may silently prevent
  downstream desync. If probes fail cleanly, the edge is
  protecting — but the underlying origin config may still be
  flawed. Note as "edge-protected; origin-layer flaw exists".

- **Smuggled request hijacks other users' auth**: If a desync
  probe surfaces another user's cookies or response, treat as
  an incident — collect evidence, IMMEDIATELY notify platform
  team, DO NOT re-run the probe.

## References

- `references/payloads.md` — full smuggling / CRLF / HTTP/2
  payload catalog

External:
- WSTG-INPV-15: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling
- CWE-444: https://cwe.mitre.org/data/definitions/444.html
- CWE-524: https://cwe.mitre.org/data/definitions/524.html
- PortSwigger HTTP Request Smuggling:
  https://portswigger.net/web-security/request-smuggling
- PortSwigger Web Cache Poisoning:
  https://portswigger.net/web-security/web-cache-poisoning

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia Técnico_ Web Cache Poisoning e HTTP Smuggling.md`

Grounded in:
- Bug Bounty Playbook V2 (Cache Poisoning)
- The Web Application Hacker's Handbook (HTTP Parsing)
- OWASP WSTG v4.2 (WSTG-INPV-15, WSTG-INPV-17)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
