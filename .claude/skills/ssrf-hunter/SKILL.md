---
name: ssrf-hunter
description: "Tests URL-fetching endpoints for Server-Side Request Forgery — loopback / internal-IP access, cloud metadata endpoints (169.254.169.254), internal-port scanning, blind SSRF via OOB callback, protocol smuggling (file:// / gopher:// / dict://), URL-parser confusion (fragment / userinfo / encoded), and DNS rebinding candidates. Use when the target has webhook / URL-fetch / link-preview / PDF-render / SVG-upload features; when parameters named `url`, `target`, `uri`, `endpoint`, `proxy` are in the inventory; or when the orchestrator's recon identifies external-fetch functionality. Produces findings with CWE-918 mapping, OOB-callback evidence, and allowlist + SSRF-safe fetcher remediation. Defensive testing only, against assets listed in .claude/security-scope.yaml."
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
  tier: T1
  source_methodology: "Guia Estratégico de Testes e Mitigação de SSRF.md"
  service_affecting: false
  composed_from: []
---

# SSRF Hunter

## Goal

Test URL-fetching functionality for Server-Side Request Forgery —
flaws that let an attacker pivot through the target's network
position to reach internal services, steal cloud credentials from
instance-metadata endpoints, perform internal port scans, or
exfiltrate data from internal systems. This skill implements
WSTG-INPV-19 and maps findings to CWE-918 (Server-Side Request
Forgery). The goal is to hand the backend / platform team a
concrete list of unprotected fetch paths with OOB callback evidence
and allowlist / SSRF-safe-fetcher remediation.

## When to Use

- The target has webhook endpoints, URL-fetch features, link
  preview / thumbnail generation, PDF rendering, file-import from
  URL, or SSO callback handlers.
- Parameters named `url`, `target`, `uri`, `path`, `endpoint`,
  `proxy`, `dest`, `src`, `webhook`, `redirect` appear in
  `API_INVENTORY.md`.
- The target is cloud-hosted (AWS / GCP / Azure) and could reach
  the instance metadata service if SSRF exists.
- The orchestrator selects this skill after `api-recon` surfaces
  URL-fetch functionality. Often runs BEFORE `aws-iam-hunter`
  (which uses SSRF findings to enumerate IMDS credentials).

## When NOT to Use

- For blind-XXE-as-SSRF via external entity URLs — use
  `xxe-hunter`; its methodology covers SSRF-adjacent XXE.
- For cloud-metadata-specific deep SSRF with IMDSv2 bypass — use
  `ssrf-cloud-metadata-hunter` (separate skill); this one covers
  standard IMDSv1 probes.
- For webhook-specific SSRF in CI/CD — `gitlab-cicd-hunter`
  handles that; this skill handles general webhooks.
- For DNS-rebinding active testing (requires controlled DNS infra)
  — flag candidates here, but full testing needs a DNS rebinding
  harness which is out of scope for this skill.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or
   doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND
   its `testing_level` is `active`.
3. SSRF testing intentionally makes the target issue requests to
   attacker-chosen destinations. Some of those destinations are
   internal. CONSTRAINTS:
   - Internal IP ranges (`10.0.0.0/8`, `172.16.0.0/12`,
     `192.168.0.0/16`, `169.254.0.0/16`) ARE in scope ONLY when
     the scope file explicitly lists `internal_ssrf_testing:
     approved`. Otherwise, restrict to public/external-host
     probes.
   - Cloud metadata IP (`169.254.169.254`) probes are permitted
     when the target is cloud-hosted AND scope approves
     metadata-service testing.
   - External destinations (for OOB detection) MUST be the
     authorized `oob_listener` from scope. NEVER use public paste
     services without explicit approval.
4. If SSRF recovers cloud credentials, STOP at the proof. Do NOT
   use the credentials to explore the cloud account — hand off to
   `aws-iam-hunter` for a read-only permission audit.
5. NO internal port scanning beyond common ports (22, 80, 443,
   3306, 5432, 6379, 8080, 8443) unless scope approves broader
   enumeration.
6. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with
   status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific URL-fetch endpoints
- `{user_a}`: authenticated session if endpoints are behind auth
- `{oob_listener}`: authorized OOB listener URL
- `{internal_targets}`: optional — explicit list of internal
  hosts/CIDRs in scope (only used if
  `internal_ssrf_testing: approved`)

## Methodology

### Phase 1: URL-Fetch Surface

1. **Inventory fetch endpoints** [Bug Bounty Bootcamp, Ch 13, p. 216]

   Do: From `API_INVENTORY.md` / `ATTACK_SURFACE.md`, filter
   endpoints that:
   - Accept URL-shaped parameters
   - Generate previews, screenshots, thumbnails
   - Import / proxy content from user-supplied URLs
   - Post webhooks on configurable destinations
   - Render PDFs from HTML URLs
   - Fetch OEmbed / oEmbed-like expansions
   - Upload-from-URL instead of direct upload

   Record: `.claude/planning/{issue}/ssrf-targets.md` with
   (endpoint, parameter, baseline-behavior-with-public-URL).

### Phase 2: Safe Baseline

2. **Baseline with harmless external URL**
   [Bug Bounty Bootcamp, Ch 13]

   Do: For each target, submit an authorized external URL (scope-
   approved OOB listener or a well-known harmless site per scope)
   and observe:
   - Response status, body
   - Response time
   - Any OOB hit on the listener

   Record: Baseline per endpoint.

### Phase 3: In-Band SSRF

3. **Loopback / localhost probes**
   [WSTG v4.2, WSTG-INPV-19, p. 1088]

   Do: For each endpoint, submit:
   ```
   http://127.0.0.1/
   http://localhost/
   http://0.0.0.0/
   http://[::1]/
   http://127.0.0.1:22/    (common internal ports)
   http://127.0.0.1:3306/
   http://127.0.0.1:6379/
   ```

   Vulnerable response: Response contains content from the
   target's own services (admin panel, management UI, Redis error,
   SSH banner in a debug message).

   Not-vulnerable response: "Invalid URL" / "Cannot fetch internal
   IP" / timeout.

   Record: Per-host / per-port findings.

4. **Cloud metadata endpoint probe**
   [Bug Bounty Bootcamp, Ch 13, p. 226]

   Do: If the target is cloud-hosted AND scope permits, try:

   AWS:
   ```
   http://169.254.169.254/latest/meta-data/
   http://169.254.169.254/latest/meta-data/iam/security-credentials/
   ```

   GCP:
   ```
   http://metadata.google.internal/computeMetadata/v1/
   (requires Metadata-Flavor: Google header — try header injection
   via URL fragment or dedicated parameter if available)
   ```

   Azure:
   ```
   http://169.254.169.254/metadata/instance?api-version=2021-02-01
   (requires Metadata: true header — same constraint as GCP)
   ```

   Vulnerable response: JSON with instance metadata, IAM role
   credentials, or environment info.

   Record: FINDING-NNN Critical. HAND OFF to `aws-iam-hunter` (or
   GCP/Azure equivalent) for credential-scope enumeration.

### Phase 4: Blind SSRF

5. **OOB callback probe**
   [Bug Bounty Bootcamp, Ch 13, p. 227]

   Do: For endpoints where the response doesn't contain fetched
   content, submit the OOB listener URL:
   ```
   https://ssrf-probe-{timestamp}.{oob_listener}/
   ```

   Watch the listener for:
   - HTTP request from the target's IP
   - DNS lookup for the subdomain

   Vulnerable response: Listener logs a hit.

   Not-vulnerable response: No hit within reasonable timeout
   (30-60s).

   Record: Per-endpoint blind-SSRF findings.

6. **Internal port scan (GATED)**
   [Bug Bounty Bootcamp, Ch 13, p. 224]

   Do: ONLY if scope approves internal enumeration AND the target
   is in an environment where scanning is authorized. For
   in-scope internal IPs:
   ```
   http://{internal-ip}:22/
   http://{internal-ip}:80/
   http://{internal-ip}:443/
   http://{internal-ip}:3306/
   http://{internal-ip}:6379/
   http://{internal-ip}:8080/
   ```

   Compare response times and status codes. Open ports typically
   respond faster than closed (immediate TCP RST) or show distinct
   error bodies.

   Vulnerable response: Differential behavior across ports reveals
   the internal network surface.

   Record: Per-IP open-port matrix. STOP at common-port set unless
   scope broadens.

### Phase 5: Protocol / URL-Parser Confusion

7. **Alternative-protocol probes**
   [WSTG v4.2, WSTG-ATHN-09, p. 1051]

   Do: Test non-HTTP schemes:
   ```
   file:///etc/passwd
   file:///c:/boot.ini
   gopher://127.0.0.1:6379/_FLUSHALL (careful — flushall is destructive)
   dict://127.0.0.1:11211/stat (memcached stats)
   ftp://internal-host/file.txt
   ldap://internal-host/
   ```

   **Avoid destructive gopher payloads** — even on in-scope, don't
   send `FLUSHALL`, `SET`, `DEL` to Redis.

   Vulnerable response: Server fetches file content, or
   interacts with internal service.

   Record: Per-scheme findings. `file://` + sensitive path reads
   are Critical.

8. **URL-parser confusion** [Bug Bounty Bootcamp, Ch 13]

   Do: Test encoding / parser-confusion bypasses:
   ```
   http://127.0.0.1%23attacker.com/
   http://attacker.com%23@127.0.0.1/
   http://attacker.com@127.0.0.1/
   http://127.0.0.1.nip.io/
   http://0x7f000001/                      (hex)
   http://0177.0.0.0x1/                    (octal+hex)
   http://2130706433/                      (decimal)
   http://127.1/                           (short-form)
   http://[::ffff:127.0.0.1]/              (IPv6-mapped IPv4)
   http://%6c%6f%63%61%6c%68%6f%73%74/     (URL-encoded)
   ```

   Vulnerable response: The parser accepts one representation but
   the SSRF-protection regex misses it.

   Not-vulnerable response: All representations rejected.

### Phase 6: DNS Rebinding Candidates

9. **DNS rebinding-candidate flagging**
   [OOB DNS]

   Do: Submit a hostname that resolves to a public IP AT FIRST
   query and switches to an internal IP on a second query. This
   requires a DNS-rebinding server setup (`rbndr.us`,
   `dns-rebinding.com`) — if scope permits, attempt with an
   authorized rebinding host.

   Vulnerable response: The target fetches an internal IP when
   the rebinding attack succeeds.

   Not-vulnerable response: Target re-resolves the hostname and
   rejects internal IPs, or caches the first resolution for long
   enough to defeat rebinding.

   Record: DNS-rebinding candidates that need follow-up with a
   dedicated rebinding lab; don't attempt actual rebinding
   without infrastructure.

## Payload Library

Full payloads in `references/payloads.md`. Categories:

- **Loopback**: `127.0.0.1`, `localhost`, `0.0.0.0`, `::1`
- **Internal-IP**: `10.x`, `172.16-31.x`, `192.168.x`
- **Cloud metadata**: AWS / GCP / Azure metadata endpoints
- **Common internal ports**: 22, 80, 443, 3306, 5432, 6379,
  8080, 8443, 9200
- **Encoding bypasses**: hex, octal, decimal, short-form,
  IPv6-mapped, URL-encoded
- **Fragment / userinfo confusion**:
  `attacker.com#target`, `attacker.com@target`
- **Protocol smuggling**: `file://`, `gopher://` (non-destructive
  only), `dict://`, `ftp://`, `ldap://`
- **OOB**: `{oob_listener}` URL for blind-SSRF

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-918 (SSRF). CWE-611 for XXE-via-SSRF (hand off to
  `xxe-hunter`). CWE-200 for internal information disclosure via
  port scanning.
- **OWASP**: WSTG-INPV-19. A10:2021 (SSRF — added in 2021). For
  APIs, API7:2023 (Server-Side Request Forgery).
- **CVSS vectors**: SSRF → cloud metadata → IAM creds —
  `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`. Internal service access
  without creds — `...C:H/I:L/A:N`. Blind SSRF only —
  `...AC:H/C:L/I:L/A:N`. `file://` to sensitive file —
  `...C:H/I:N/A:N`.
- **Evidence**: the injected URL, the response containing internal
  content (or OOB listener log), and the fingerprinted internal
  service if applicable.
- **Remediation framing**: backend engineer + platform. Include:
  - Allowlist of permitted fetch destinations (domains AND
    resolved IPs — resolve and re-check before fetch)
  - SSRF-safe fetcher libraries (e.g., Python `ssrf_safe`, Ruby
    `ssrf_filter`, Node `ssrf-req-filter`)
  - Network-level egress filtering from the application subnet
    (block RFC 1918, link-local, loopback)
  - IMDSv2 enforcement (AWS) — blocks basic SSRF even if app
    SSRF exists
  - Protocol allowlist (HTTPS only, not file/gopher/ftp)
  - Response sanitization if fetched content is displayed (don't
    pass internal content back raw)

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
- `.claude/planning/{issue}/aws-iam-targets.md` — appends SSRF
  vectors reaching IMDS for `aws-iam-hunter`

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every finding includes the injection URL AND the resulting
      response / OOB log
- [ ] Cloud-credential discoveries were NOT used to explore the
      account beyond the proof — handed off to `aws-iam-hunter`
- [ ] Internal-IP probes stayed within scope-declared
      internal_targets, or used `internal_ssrf_testing: approved`
      blanket permission
- [ ] No destructive gopher payloads (FLUSHALL / DEL / etc.) were
      sent
- [ ] Port scan limited to common-port set unless scope broadens
- [ ] OOB listener used is in the scope's allowlist
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Safe reflection without fetch**: The URL appears in the
  response body but the server didn't actually fetch it. Confirm
  SSRF with OOB callback or differential-response evidence.

- **Intentional open proxy**: Some apps are designed as URL fetchers
  (link-preview services, translation tools). External fetch is
  intended; the vulnerability is only internal reachability. File
  findings for the internal reach, not the public-fetch feature.

- **Network latency misread as port hit**: Slow responses may be
  server load, not a port response. Compare multiple probes with
  different IPs to baseline timing.

- **DNS-only blind SSRF**: The OOB listener logs only a DNS
  lookup, not an HTTP request. This proves DNS resolution
  happens (so hostname parsing is server-side), but doesn't
  prove HTTP fetch. Lower severity than HTTP-verified blind SSRF.

- **IMDSv2 protection**: AWS instances with IMDSv2 enforced
  reject IMDS requests without a session token. Basic SSRF
  payloads fail even if SSRF exists. File as "SSRF confirmed,
  IMDS inaccessible due to IMDSv2 — verify no IMDSv1 fallback".
  Cross-reference `aws-iam-hunter` Phase 4.

- **WAF blocks SSRF attempts**: Some WAFs block internal-IP
  patterns in URL parameters. The WAF is a defense; file as
  "SSRF exists but externally blocked by WAF — fix the
  application layer regardless".

- **Circular vs actual internal**: `127.0.0.1` from the target's
  perspective is the target itself, not a pivot. Internal IPs
  like `10.0.0.5` reach distinct machines. Both are SSRF
  findings but severity differs.

## References

- `references/payloads.md` — full encoding-and-protocol bypass
  payload catalog

External:
- WSTG-INPV-19: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery
- CWE-918: https://cwe.mitre.org/data/definitions/918.html
- OWASP SSRF Prevention Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger SSRF labs:
  https://portswigger.net/web-security/ssrf

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia Estratégico de Testes e Mitigação de SSRF.md`

Grounded in:
- Bug Bounty Bootcamp, Ch 13 (SSRF)
- Bug Bounty Playbook V2 (SSRF chapter)
- OWASP WSTG v4.2 (WSTG-INPV-19, WSTG-ATHN-09)
- OWASP API Security Top 10 (API7:2023)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
