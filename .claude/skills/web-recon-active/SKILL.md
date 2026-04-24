---
name: web-recon-active
description: "Performs active web-application reconnaissance — port scanning, spidering, directory brute-forcing, HTTP method enumeration, hidden-parameter discovery, and API spec hunting — against in-scope targets. Use as a foundational skill before any hunter-class assessment; the output feeds idor-hunter, sqli-hunter, and every class-specific hunter. Run AFTER web-recon-passive (so we don't re-discover publicly-known surface). Produces an attack-surface inventory written to .claude/planning/{issue}/ATTACK_SURFACE.md. Defensive testing only, against assets listed in .claude/security-scope.yaml."
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
  source_methodology: "Guia de Reconhecimento Ativo em Aplicações Web.md"
  service_affecting: true
  composed_from: []
---

# Web Recon (Active)

## Goal

Build a complete attack-surface inventory for in-scope web applications
by sending probes directly to the target — port scans, HTTP spidering,
directory brute-forcing, hidden-parameter discovery, and HTTP method
enumeration. This skill implements WSTG-INFO-01 through WSTG-INFO-10 and
produces the inventory that downstream hunter skills consume. No
vulnerability findings are produced by this skill directly; its output is
the scoping document that makes all other skills efficient.

## When to Use

- At the start of a security assessment, after `web-recon-passive` has
  run — passive recon avoids issuing probes for surface we can learn
  from OSINT alone.
- When a target's attack surface is unknown and the scope file allows
  active testing.
- Before any hunter skill runs — the hunter skills expect an inventory
  document to exist.
- When the orchestrator's phase-0 planning calls for active web-surface
  mapping.

## When NOT to Use

- For surface that's already mapped in a recent recon run (<7 days old)
  — re-read the existing inventory instead of re-scanning.
- For API-first targets (REST / GraphQL / gRPC without a web UI) — use
  `api-recon` instead; it has API-specific probes (OpenAPI/Swagger
  discovery, GraphQL introspection, HTTP-method fuzzing).
- For purely-internal discovery where the scope file specifies passive
  only — use `web-recon-passive`.
- For authenticated-only surface discovery — this skill can be run
  authenticated, but its primary mode is unauthenticated. For
  authenticated spidering, pass `{user_a}` session.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or
   doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND its
   `testing_level` is `active`.
3. This skill's `service_affecting: true` flag means active probes
   (directory brute-forcing, port scans, parameter fuzzing) generate
   real traffic. Confirm the asset's `service_affecting` field is
   `approved` — if `denied`, halt and request explicit user approval
   for this target.
4. Apply the scope file's `rate_limit_rps` — default 10 req/sec if
   unspecified, but honor per-environment overrides (production
   typically 5 rps).
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with
   status `running`. Include the asset and the rate-limit in force.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific paths or subdomains to focus on
- `{user_a}`: optional — authenticated session (enables authenticated
  spidering for richer inventory)
- `{wordlist_dir}`: path to directory/parameter wordlists (default:
  `/usr/share/seclists/`)

## Methodology

### Phase 1: Service and Version Fingerprinting

1. **Port and service discovery** [Hacking APIs, Ch 6, p. 215]

   Do: Run a safe Nmap scan against the target: `nmap -sC -sV -Pn
   --script=safe -oA .claude/planning/{issue}/recon/nmap-{target}
   {target}`. Stick to `--script=safe` profile — destructive scripts are
   blocked by tool profile.

   Vulnerable response: Ports beyond 80/443 open (unnecessary services
   exposed); version banners revealing CVE-ridden software.

   Not-vulnerable response: Minimal production ports exposed; banners
   genericized.

   Record: Port/service matrix in
   `.claude/planning/{issue}/ATTACK_SURFACE.md` under "Services".

2. **HTTP header fingerprinting** [WSTG v4.2, 4.1.2, p. 1035]

   Do: `httpx -title -status-code -web-server -tech-detect -u
   https://{target}/` — captures Server, X-Powered-By, CSP headers, and
   detects web frameworks via Wappalyzer signatures.

   Vulnerable response: Version-disclosing headers (e.g.,
   `Server: Apache/2.4.18`, `X-Powered-By: PHP/5.4.7`).

   Not-vulnerable response: Headers genericized or absent.

   Record: Tech stack in `ATTACK_SURFACE.md` under "Stack".

### Phase 2: Site Mapping and Spidering

3. **Automated spidering** [WAHH, Ch 4, p. 74; WSTG v4.2, 4.1.7]

   Do: Use an authenticated or unauthenticated spider (e.g.,
   `gospider -s https://{target} -d 3 -c 5`) to enumerate linked pages,
   forms, and static assets. Feed the output into
   `.claude/planning/{issue}/recon/spider.txt`.

   If `{user_a}` is provided, re-run with the session cookie to
   discover authenticated-only paths (`/admin`, `/account/settings`).

   Vulnerable response: Unlinked admin pages, developer tools, or
   sensitive paths reachable from the public tree.

   Record: URL tree in `ATTACK_SURFACE.md` under "Paths".

4. **Wayback / gau URL harvest** [zseano's methodology]

   Do: `gau {target} | tee
   .claude/planning/{issue}/recon/gau-urls.txt` — fetches historical
   URLs known to Wayback Machine, Common Crawl, OTX, etc. Filter for
   paths the live spider missed.

   Record: Deprecated-but-still-live endpoints are highest value
   (often forgotten by defenders).

### Phase 3: Directory and File Brute-Forcing

5. **Directory enumeration** [WAHH, Ch 4, p. 82]

   Do: `ffuf -u https://{target}/FUZZ -w
   {wordlist_dir}/Discovery/Web-Content/common.txt -mc 200,204,301,302,307,401,403
   -rate {rate_limit_rps}` — enumerate likely directories using a
   common wordlist, honoring the scope rate limit.

   Vulnerable response: `/admin`, `/.git`, `/backup`, `/config`,
   `/phpmyadmin`, or `.bak`/`.old`/`.swp` files that weren't linked.

   Not-vulnerable response: Consistent 404 for all wordlist entries.

   Record: Accessible-but-unlinked paths in
   `ATTACK_SURFACE.md` under "Hidden Paths".

6. **Extension fuzzing on known paths** [WSTG v4.2, 4.1.8]

   Do: For each interesting endpoint discovered (e.g., `/login`), test
   extension variants: `ffuf -u https://{target}/login.FUZZ -w
   extensions.txt -mc 200` testing `.bak`, `.old`, `.orig`, `.swp`,
   `.zip`, `.tar.gz`, `.sql`.

   Record: Any exposed source-code or backup file is a finding — file
   to SECURITY_AUDIT.md under `secrets-in-code-hunter` cross-reference.

### Phase 4: Input Surface Discovery

7. **Parameter and form inventory** [WAHH, Ch 4, p. 98]

   Do: From the spider output, extract every URL with query parameters
   and every HTML form. Use `unfurl keys < spider.txt | sort -u` to
   list unique parameter names.

   Record: Parameter inventory in `ATTACK_SURFACE.md` under "Inputs",
   grouped by endpoint.

8. **Hidden-parameter discovery** [WAHH, Ch 4, p. 97]

   Do: For each endpoint, run `arjun -u "https://{target}/{path}" -m
   GET,POST --rate-limit {rate_limit_rps} -t 5` with the default
   parameter wordlist. Also test permutation of names common for
   feature-flag toggles: `debug`, `test`, `admin`, `preview`, `source`,
   `trace`, `verbose`.

   Vulnerable response: The endpoint's response changes when a
   previously-unknown parameter is added.

   Record: Hidden-parameter inventory in `ATTACK_SURFACE.md` under
   "Hidden Inputs".

9. **HTTP method enumeration** [WSTG v4.2, 4.2.6]

   Do: For each endpoint, run `curl -X OPTIONS
   https://{target}/{path}` to see advertised methods; also fuzz `PUT
   / DELETE / PATCH / TRACE` if the documented method is `GET`.

   Vulnerable response: Dangerous methods accepted (e.g., `TRACE`
   reflects request headers — Cross-Site Tracing; `PUT` accepted on a
   static path — file upload).

   Record: Per-endpoint method allow-list.

### Phase 5: API-Spec and Documentation Discovery

10. **Documentation-path hunting** [Hacking APIs, Ch 7, p. 156]

    Do: Probe common doc/spec paths:
    ```
    /swagger.json
    /openapi.json
    /v1/swagger/
    /api-docs/
    /graphql
    /graphiql
    /.well-known/openid-configuration
    /.well-known/security.txt
    /robots.txt
    /sitemap.xml
    /humans.txt
    ```
    Also test version markers: `/v1/`, `/v2/`, `/v3/`, `/internal/`,
    `/legacy/`.

    Vulnerable response: Full API spec disclosing endpoints, parameters,
    and auth requirements; a `/v1/` still active after v2 shipped.

    Record: Available specs in `ATTACK_SURFACE.md` under "API Docs";
    feed directly to `api-recon` if the target is API-heavy.

## Payload Library

No exploit payloads — this is reconnaissance. The key probe patterns
inline in this skill are:

- **Baseline port scan**: `nmap -sC -sV -Pn --script=safe`
- **Directory wordlists**: common.txt, raft-medium-directories.txt,
  kitrunner for API paths
- **Hidden-parameter wordlists**: Arjun default, plus `debug,test,
  admin,preview,source,trace,verbose`
- **Method fuzz**: `OPTIONS, TRACE, PUT, DELETE, PATCH, CONNECT`
- **Doc paths**: swagger/openapi, graphql/graphiql, well-known

## Output Format

This skill does NOT directly append findings to SECURITY_AUDIT.md. Its
output is an **inventory document** that other skills consume:

- `.claude/planning/{issue}/ATTACK_SURFACE.md` — the primary artifact,
  structured as:
  - **Services** (port + version matrix)
  - **Stack** (web server, framework, CDN, WAF)
  - **Paths** (URL tree, spider + gau)
  - **Hidden Paths** (brute-force hits)
  - **Inputs** (parameters per endpoint)
  - **Hidden Inputs** (arjun hits)
  - **Method Matrix** (per-endpoint HTTP methods)
  - **API Docs** (spec paths)

When this skill DOES append a finding to SECURITY_AUDIT.md, it's for
clearly-exploitable discoveries that don't belong in a class-specific
hunter — specifically:

- **Exposed backup files / source code** → CWE-538 (Insertion of
  Sensitive Information into Externally-Accessible File or Directory)
- **Dangerous HTTP methods enabled** → CWE-650 (TRACE) or CWE-200
- **Open dev/staging environments** → CWE-200

Severity for each: Medium, unless the exposed file contains
credentials (then High) or is an actively-used admin path (High).

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
  (noting "attack surface inventory complete")
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] ATTACK_SURFACE.md is populated across all 8 sections (or sections
      marked "none found")
- [ ] The rate limit in the scope file was honored (check scan logs)
- [ ] No out-of-scope subdomains were scanned (grep scan output against
      scope file)
- [ ] The authenticated pass was run if `{user_a}` was provided
- [ ] Every directory/file brute-force wordlist was pre-approved (no
      "raft-large" or "directory-list-2.3-big" unless scope OKs)
- [ ] No aggressive Nmap script categories were run (only
      `--script=safe`)
- [ ] Any exposed source/backup files are flagged for
      `secrets-in-code-hunter`
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Controlled chaos (deception)**: Defenders intentionally add bogus
  files and folders from frameworks the app doesn't use, to waste
  scanner time. If `/wp-admin/` returns 200 but the stack is clearly
  Rails, it's probably a honeypot; confirm before noise-filling the
  inventory.

- **Catch-all 200 responses**: Some apps return HTTP 200 for every
  request, with a "Page not found" body. Use response-size diffing
  instead of status-code matching — `ffuf -fs {baseline_404_size}` to
  filter out the catchall.

- **Load-induced anomalies**: Aggressive rate can cause timeouts or
  500s that look like vulnerabilities (time-based SQLi false
  positives). Stay at or below the scope rate limit and re-run
  suspicious results at single-request cadence.

- **Internal vs external views**: Production is often fronted by a CDN
  or WAF that masks the real server banner. Note when recon is
  CDN-terminated — findings may differ from an internal-network view.

- **Authenticated spidering vs. session corruption**: Spidering as
  `{user_a}` can accidentally trigger state changes (e.g., following a
  "Delete" link in an admin tool). Configure the spider to avoid
  known-destructive verbs and paths.

## References

External:
- WSTG-INFO family: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/
- ffuf: https://github.com/ffuf/ffuf
- httpx: https://github.com/projectdiscovery/httpx
- arjun: https://github.com/s0md3v/Arjun
- gospider: https://github.com/jaeles-project/gospider
- SecLists: https://github.com/danielmiessler/SecLists

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia de Reconhecimento Ativo em Aplicações Web.md`

Grounded in:
- Hacking APIs, Ch 6 (Active Recon)
- The Web Application Hacker's Handbook, Ch 4 (Mapping the Application)
- OWASP WSTG v4.2 (Section 4.1, Information Gathering)
- Bug Bounty Bootcamp, Ch 5-7 (Recon)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
