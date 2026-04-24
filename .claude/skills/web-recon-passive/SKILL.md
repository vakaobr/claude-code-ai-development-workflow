---
name: web-recon-passive
description: "Performs passive reconnaissance against in-scope targets using only public OSINT sources — search engines, DNS history, Wayback Machine, public code repositories, metadata in published files, and .well-known files on the live site (no intrusive probing). Use as the first foundational skill of an assessment; results feed web-recon-active and api-recon. Produces an OSINT dossier written to .claude/planning/{issue}/PASSIVE_RECON.md. Defensive testing only, against assets listed in .claude/security-scope.yaml."
model: sonnet
allowed-tools: Read, Grep, Glob, WebFetch(domain:*.in-scope-domain.com)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: recon
  authorization_required: true
  tier: T4
  source_methodology: "Guia de Reconhecimento Passivo em Aplicações Web.md"
  service_affecting: false
  composed_from: []
---

# Web Recon (Passive)

## Goal

Build the first-pass OSINT dossier for in-scope targets using only
publicly-available sources, so that subsequent active recon can be
narrower and more efficient. This skill implements WSTG-INFO-01 through
WSTG-INFO-05 (passive sections) and produces the dossier that
`web-recon-active` and `api-recon` consume. No vulnerability findings
from this skill alone unless credentials or sensitive data are
discovered in public sources — those escalate to SECURITY_AUDIT.md
immediately.

## When to Use

- At the very start of an assessment — passive recon runs before
  active to avoid re-discovering surface OSINT already reveals.
- When the scope file restricts testing to `passive_only` (production
  environments typically default to this).
- When the assessment window is constrained and OSINT-level findings
  may be sufficient before escalating to active probes.
- When the orchestrator's phase-0 plan selects it as the first step.

## When NOT to Use

- When active probes are needed to confirm that OSINT-surfaced
  endpoints are still live — that's `web-recon-active`'s job.
- For deep API-spec enumeration — use `api-recon` (includes both
  passive and active phases).
- For the one-off credential verification that's part of a leaked-key
  investigation — use `secrets-in-code-hunter` (which cross-references
  `aws-iam-hunter` for key validation).
- Any asset not listed in `.claude/security-scope.yaml`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or
   doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND its
   `testing_level` is at least `passive`.
3. Passive recon uses only third-party OSINT sources (search engines,
   Wayback, GitHub) and at most a small number of direct GETs against
   public, non-authenticated paths (`/robots.txt`, `/sitemap.xml`,
   `/.well-known/*`). None of these should trigger the asset's
   `service_affecting` concern.
4. If the target is ambiguous, write it to
   `.claude/planning/{issue}/SCOPE_QUESTIONS.md` and halt for that
   target only.
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with
   status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier (hostname, domain, or org name)
- `{scope_context}`: optional — apex domain or sibling assets to
  cross-reference

## Methodology

### Phase 1: Search Engine Discovery

1. **Advanced search operators (dorks)** [WSTG v4.2, 4.1.1]

   Do: Use WebFetch to query search engines (or use the user's browser
   via documented URLs) with dorks:
   ```
   site:{target} filetype:pdf
   site:{target} filetype:xls OR filetype:xlsx OR filetype:doc
   site:{target} inurl:admin OR inurl:login OR inurl:dashboard
   site:{target} "index of /"
   site:{target} "error" "stack trace"
   "{target}" "api_key" OR "api-key" OR "apikey"
   ```

   Vulnerable condition: Indexed documents contain internal URLs,
   usernames, or configuration details; stack traces reveal backend
   paths.

   Record: Hits in `.claude/planning/{issue}/passive-recon/search-hits.md`.

2. **File-metadata pulls**
   [WSTG v4.2, 4.1.5]

   Do: Download any indexed office files (PDFs, DOCXs) and run
   `exiftool` / `pdfinfo` to extract metadata — author names,
   internal paths, software versions.

   Record: Leaked usernames / paths in the passive-recon file.

### Phase 2: DNS and Subdomain Enumeration (Passive)

3. **Subdomain enumeration via passive sources**
   [Hacking APIs, Ch 6, p. 131]

   Do: `amass enum -passive -d {target}` or equivalent Crt.sh,
   SecurityTrails, Chaos DB, DNSDumpster queries. All use
   already-indexed data — no direct DNS fuzzing against the target.

   Vulnerable condition: Dev/staging subdomains appear
   (`dev.{target}`, `staging.{target}`, `backup.{target}`) — Improper
   Asset Management candidates.

   Record: Subdomain list in
   `.claude/planning/{issue}/passive-recon/subdomains.txt`.

4. **Certificate Transparency log review**
   [WSTG v4.2, 4.1.3]

   Do: Query CT logs (`crt.sh`, Google CT, Facebook CT) for all
   certificates issued to `*.{target}`. Extract SAN entries.

   Vulnerable condition: Internal-looking hostnames appear in public
   CT logs (`internal.{target}`, `vpn.{target}`, `jump-box.{target}`).

   Record: Hostnames from CT + their issue dates.

### Phase 3: Historical Asset Discovery

5. **Wayback Machine harvest**
   [Bug Bounty Bootcamp, Ch 5, p. 62]

   Do: Query `web.archive.org` for historical snapshots of `{target}`.
   `gau -subs {target}` and `waybackurls {target}` compile URL lists
   from multiple historical sources.

   Vulnerable condition: URLs for decommissioned endpoints may still
   be reachable; old JavaScript bundles may reveal deprecated API
   paths and parameter names.

   Record: URL list + notable deprecated paths in
   `passive-recon/historical-urls.txt`.

### Phase 4: Public Code Repository Search

6. **GitHub / GitLab / Bitbucket OSINT**
   [Hacking APIs, Ch 6, p. 133]

   Do: Search public code-hosting platforms for the organization's
   name + sensitive keywords:
   ```
   "{org_name}" filename:.env
   "{org_name}" "API_KEY"
   "{org_name}" AKIA
   "{org_name}" "BEGIN RSA PRIVATE KEY"
   org:{org_name} path:config.json
   ```

   Use `gh` CLI or web interface — do NOT use third-party "search
   everything" tools without scope approval.

   Vulnerable condition: Valid API keys, AWS access keys, JWTs, or
   private RSA keys in commit history.

   Record: Each hit in `passive-recon/code-hits.md` with
   (repo, file, line, captured-secret-hash). Hash the secret value;
   don't store plaintext.

   **Escalation**: Valid credentials go to a findings file IMMEDIATELY
   with a rotation request, independent of the rest of the recon
   output. Cross-reference `secrets-in-code-hunter` for repo-history
   deep-dive and `aws-iam-hunter` for AWS key validation.

### Phase 5: On-Site Passive Signals

7. **Fingerprint via response headers** [WSTG v4.2, 4.1.2]

   Do: Single `WebFetch https://{target}/` (or `/robots.txt`) and
   inspect the response. Note:
   - `Server`
   - `X-Powered-By`
   - `X-AspNet-Version`
   - `X-Generator`
   - `Set-Cookie` (framework hints via cookie names: `PHPSESSID`,
     `JSESSIONID`, `connect.sid`, `laravel_session`)

   Vulnerable condition: Headers disclose exact software versions
   (search for CVEs).

   Record: Tech fingerprint in `passive-recon/fingerprint.md`.

8. **Metafile review** [WSTG v4.2, 4.1.3]

   Do: Fetch:
   - `https://{target}/robots.txt`
   - `https://{target}/sitemap.xml`
   - `https://{target}/humans.txt`
   - `https://{target}/.well-known/security.txt`
   - `https://{target}/.well-known/openid-configuration`
   - `https://{target}/.well-known/change-password`

   Vulnerable condition: `robots.txt` lists paths the app wants
   hidden (e.g., `/admin/`, `/internal/`, `/api/beta/`);
   `sitemap.xml` leaks every page; `security.txt` absent (compliance
   / best-practice gap).

   Record: Any sensitive paths from metafiles in
   `passive-recon/metafiles.md`.

9. **Source-code comment review** [WSTG v4.2, 4.1.5]

   Do: WebFetch the main page + any linked JavaScript bundles.
   `grep -nE "(<!--|/\*|//)" <fetched.html>` to find HTML/JS
   comments. Look for internal IPs, usernames, SQL snippets, debug
   flags.

   Vulnerable condition: Comments disclose internal logic, IPs,
   or debug toggles.

   Record: Leaked comments in `passive-recon/comments.md`.

## Payload Library

No payloads — this skill only reads public sources. Key probe
patterns:

- **Google dorks**: filetype:, inurl:, site:, intitle:
- **GitHub dorks**: `org:X filename:Y`, `org:X "KEYWORD"`
- **Passive subdomain tools**: amass passive, crt.sh, securitytrails,
  dnsdumpster
- **Wayback / gau**: historical URL harvests
- **Metafile paths**: `/robots.txt`, `/sitemap.xml`,
  `/.well-known/security.txt`

## Output Format

This skill produces the **PASSIVE_RECON.md dossier** that downstream
recon and hunter skills consume:

- `.claude/planning/{issue}/PASSIVE_RECON.md` — structured as:
  - **Organization** (apex, legal entity, org identifiers)
  - **Subdomains** (passive-sourced + CT log)
  - **Historical URLs** (Wayback + gau highlights)
  - **Tech Fingerprint** (headers, framework cookies, CDN/WAF)
  - **Metafiles** (robots.txt, sitemap.xml, .well-known/*)
  - **Leaked Assets** (documents, code-repo hits, search-engine hits)
  - **Public Credentials** (cross-referenced to the findings file)

Findings appended to SECURITY_AUDIT.md only when OSINT surfaces
something immediately exploitable:

- **Leaked credentials** → CWE-798, severity High (before rotation)
- **Exposed configuration files** (`.env`, `config.json`) → CWE-538,
  severity depends on content
- **Public dev/staging with production data** → CWE-200 + API9:2023
  — Improper Asset Management

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] PASSIVE_RECON.md has all 7 sections populated (or marked "none")
- [ ] No direct active probes against the target were run (grep the
      skill's action log for anything beyond WebFetch to
      public-path URLs)
- [ ] Captured secrets are hash-stored, not plaintext-stored
- [ ] Every leaked-credential hit has a matching entry in the
      SECURITY_AUDIT findings file, not just the dossier
- [ ] Cross-references to `web-recon-active`, `api-recon`,
      `secrets-in-code-hunter` are noted so follow-up skills don't
      duplicate work
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Stale archives**: Wayback / gau often show URLs that are no
  longer live. Distinguish in the dossier between "historical" and
  "confirmed live" — the latter requires active probing, which is
  `web-recon-active`'s scope.

- **Honeytokens in public repos**: Some orgs intentionally commit fake
  credentials with monitoring to catch attackers. Validating a public
  key (via `aws sts get-caller-identity` in `aws-iam-hunter`) may
  trigger an incident. Coordinate with the org's security team before
  validating suspiciously-public keys.

- **Body-embedded errors**: An app can return HTTP 200 with a
  "not found" body. Passive recon can't distinguish without active
  probing — note the URL but defer confirmation to
  `web-recon-active`.

- **Search index lag**: A recent incident or config change may not
  appear in search indexes yet; Wayback typically lags 1-4 weeks.
  Passive findings always have an "as of {date}" caveat; active recon
  should confirm.

- **Scope-adjacent hits**: OSINT for `{org}` often returns hits for
  sibling brands, subsidiaries, or M&A-acquired assets that aren't
  in scope. Filter ruthlessly against the scope file's asset list.

## References

External:
- WSTG-INFO family: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/
- amass: https://github.com/owasp-amass/amass
- gau: https://github.com/lc/gau
- waybackurls: https://github.com/tomnomnom/waybackurls
- crt.sh: https://crt.sh
- exiftool: https://exiftool.org

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia de Reconhecimento Passivo em Aplicações Web.md`

Grounded in:
- Hacking APIs, Ch 6 (Passive Recon)
- Bug Bounty Bootcamp, Ch 5 (Recon)
- OWASP WSTG v4.2 (Section 4.1, Information Gathering — passive)
- zseano's methodology (Methodology Chapter)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
