---
name: subdomain-takeover-hunter
description: "Audits DNS records for dangling subdomain takeover risk — CNAMEs pointing at unclaimed GitHub Pages / S3 buckets / Heroku apps / Azure / Fastly / Shopify; NS records delegating to expired nameservers; and dedicated-service signatures ('There isn't a GitHub Pages site here', 'NoSuchBucket'). Passive-only — only DNS lookups and HTTP fetches. Does NOT claim the subdomain (that's operator-level action requiring explicit scope approval). Use after `web-recon-passive` surfaces subdomain inventory from CT logs and passive DNS. Produces findings with CWE-350 mapping and 'remove-dangling-record' + lifecycle-management remediation. Defensive testing only, against assets listed in .claude/security-scope.yaml."
model: sonnet
allowed-tools: Read, Grep, Glob, WebFetch(domain:*.in-scope-domain.com)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: recon
  authorization_required: true
  tier: T2
  source_methodology: "Guia Técnico de Subdomain Takeover_ Detecção e Mitigação.md"
  service_affecting: false
  composed_from: []
---

# Subdomain Takeover Hunter

## Goal

Audit DNS records for dangling subdomain-takeover risk — CNAMEs
pointing at third-party services (GitHub Pages, AWS S3, Heroku,
Azure, Fastly, Shopify, Netlify, Webflow, etc.) where the
underlying resource is deleted or unclaimed, letting an attacker
register the dangling target and serve content from the victim's
subdomain. Also covers NS-record takeover (nameserver delegated to
an expired domain). This skill implements WSTG-CONF-10 and maps
findings to CWE-350 (Reliance on Reverse DNS Resolution) for the
trust-model issue. The goal is to hand the platform team a
concrete list of dangling records with remove-and-monitor
remediation. This skill DOES NOT claim dangling subdomains —
claiming requires scope-approved operator action.

## When to Use

- `web-recon-passive` has collected a subdomain inventory (from
  CT logs, passive DNS, Amass passive mode).
- The organization uses third-party SaaS services (XaaS) that
  accept custom domain mappings.
- The orchestrator selects this skill after subdomain enumeration
  surfaces candidates pointing at `*.github.io`, `*.s3.amazonaws.com`,
  `*.herokuapp.com`, `*.fastly.net`, etc.
- A recent infrastructure change (decommissioned service, moved
  CDN) could have left dangling records.

## When NOT to Use

- For discovering new subdomains (that's `web-recon-passive` /
  `api-recon`).
- For actively claiming dangling subdomains to prove exploitability
  — that's operator-level action requiring explicit scope
  approval; this skill only IDENTIFIES candidates.
- For subdomain-takeover of internal DNS zones — this skill
  focuses on public DNS; internal zone review is a different
  engagement.
- For non-DNS-based takeover (e.g., SSO-domain trust
  relationships) — out of scope.
- Any asset not listed in `.claude/security-scope.yaml`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist
   or doesn't parse, halt and report.
2. Confirm the target apex domain appears in the `assets` list
   AND its `testing_level` is at least `passive`. This skill
   performs DNS queries and single HTTP GETs against subdomains
   — standard passive activity.
3. **Never attempt to claim a dangling subdomain.** Claiming
   requires:
   - Registering on the third-party service
   - Setting up evidence content
   - Leaving an auditable footprint
   These steps cross into exploitation and need explicit
   `subdomain_takeover_claim: approved` in scope. Without that,
   this skill STOPS at the detection step — the finding is
   "dangling record pointing at {third-party-service}", not
   "takeover confirmed by claim".
4. For subdomains showing unclaimed-service signatures, note the
   finding and recommend that the platform team either: (a)
   remove the dangling record, or (b) intentionally claim the
   resource to prevent malicious claim.
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
   with status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the apex domain (e.g., `example.com`)
- `{subdomain_inventory}`: path to `web-recon-passive`'s
  subdomain list
- `{scope_context}`: optional — specific subdomains to prioritize

## Methodology

### Phase 1: DNS-Record Enumeration

1. **Resolve each subdomain for A / CNAME / NS**
   [WSTG v4.2, 4.2.10, p. 1041]

   Do: For each subdomain in the inventory, run:
   ```bash
   dig +short {subdomain}
   dig +short CNAME {subdomain}
   dig +short NS {subdomain}
   ```

   Capture the full DNS chain. A CNAME to another CNAME is a
   redirect chain; follow to the final answer.

   Record:
   `.claude/planning/{issue}/subdomain-takeover-dns.md` with
   (subdomain, record type, target, chain length).

2. **NXDOMAIN / SERVFAIL detection**
   [WSTG v4.2, 4.2.10, p. 1041]

   Do: For the final DNS target, check resolution status:
   - `NXDOMAIN` → domain doesn't exist (takeover candidate)
   - `SERVFAIL` → name server can't resolve (check if NS is
     dangling)
   - `REFUSED` → authoritative server refused (rare, worth noting)

   Vulnerable signal: CNAME points at NXDOMAIN, or NS points at
   a domain that NXDOMAINs.

   Record: Per-subdomain DNS health.

### Phase 2: Third-Party-Service Signature Matching

3. **Service fingerprinting via CNAME target**
   [Bug Bounty Bootcamp, Ch 20, p. 316]

   Do: Match CNAME targets against known third-party services
   prone to takeover:
   ```
   *.github.io           → GitHub Pages
   *.s3.amazonaws.com    → AWS S3
   *.s3-website*.amazonaws.com  → AWS S3 Website
   *.cloudfront.net      → AWS CloudFront
   *.herokuapp.com       → Heroku
   *.herokudns.com       → Heroku
   *.azurewebsites.net   → Azure App Service
   *.trafficmanager.net  → Azure Traffic Manager
   *.cloudapp.net        → Azure Cloud Services (legacy)
   *.fastly.net          → Fastly
   *.myshopify.com       → Shopify
   *.netlify.app         → Netlify
   *.webflow.io          → Webflow
   *.zendesk.com         → Zendesk
   *.tumblr.com          → Tumblr
   *.readthedocs.io      → Read the Docs
   *.intercom.com        → Intercom
   *.pantheonsite.io     → Pantheon
   *.wordpress.com       → WordPress
   *.uservoice.com       → UserVoice
   *.squarespace.com     → Squarespace
   *.strikingly.com      → Strikingly
   *.surge.sh            → Surge
   *.ngrok.io            → ngrok (dev-only; should never be in prod DNS)
   ```

   Record: Per-subdomain → service-provider mapping.

### Phase 3: Liveness + Signature Check

4. **HTTP GET with signature matching**
   [WSTG v4.2, 4.2.10, p. 1042]

   Do: For each subdomain pointing at a known-takeover-prone
   service, fetch via `WebFetch`:
   ```
   GET https://{subdomain}/
   GET http://{subdomain}/  (some services only respond on HTTP)
   ```

   Match response bodies against unclaimed-service signatures:
   ```
   GitHub Pages:    "There isn't a GitHub Pages site here"
   AWS S3:          "NoSuchBucket" / "The specified bucket does not exist"
   Heroku:          "No such app" / "no-such-app" image
   Azure App:       "404 Web Site not found" / Azure-branded 404
   Fastly:          "Fastly error: unknown domain"
   Shopify:         "Sorry, this shop is currently unavailable" (sometimes)
   Netlify:         "Not Found - Request ID" or default 404
   Webflow:         "The page you are looking for doesn't exist"
   Zendesk:         "Help Center Closed"
   Tumblr:          "There's nothing here"
   Readme:          "Project doesnt exist... yet!"
   ngrok:           "Tunnel *.ngrok.io not found"
   ```

   Vulnerable response: Signature matches a known unclaimed
   pattern.

   Not-vulnerable response: Legitimate content, or a target-owned
   404 (no third-party signature).

   Record: Per-subdomain — signature hit + service name.

### Phase 4: NS-Record Takeover

5. **Check NS target-domain registration**
   [WSTG v4.2, 4.2.10, p. 1043]

   Do: For each NS record, extract the target domain (e.g.,
   `ns1.abandoned-dns-provider.com`). Whois-query the target's
   apex to see if it's:
   - Registered to a legitimate party (safe)
   - Available for purchase (critical takeover candidate)
   - Registered to an unrelated party (suspicious — possible
     prior takeover)

   ```bash
   whois $(echo "ns1.provider.com" | awk -F. '{print $(NF-1)"."$NF}')
   ```

   Vulnerable response: The NS target's parent domain is
   available for registration.

   Record: FINDING-NNN Critical — NS takeover lets the attacker
   control the ENTIRE subdomain's DNS zone.

### Phase 5: Dormant-Service Detection

6. **Check for "Getting Started" / default-content pages**
   [Bug Bounty Bootcamp, Ch 20, p. 316]

   Do: Some services return a "Welcome to {service}. Get started"
   page for subdomains that are technically claimed but point at
   an empty account. Use screenshot tools (EyeWitness, Aquatone)
   or visual comparison to identify these.

   If WebFetch shows a default-welcome page for an otherwise-
   quiet subdomain:
   - The subdomain could be actively-claimed but abandoned
     (still a maintenance finding)
   - Or it could be the default-page pre-claim (also a finding)

   Record: "Dormant content" candidates for manual review.

### Phase 6: Recommendation Synthesis

7. **Per-subdomain recommendation**
   [WSTG v4.2, 4.2.10, p. 1043]

   Do: For each FINDING-NNN, include the recommended action:

   - **Remove dangling record**: if the third-party resource is
     genuinely no longer used, simply delete the CNAME. This is
     usually the correct answer.
   - **Re-claim the resource**: if the subdomain should continue
     to serve content (e.g., a public-facing app), re-claim the
     third-party resource with the original DNS mapping to
     prevent malicious claim.
   - **Add verification**: some services (newer AWS, newer Azure)
     support per-domain verification (TXT records) that prevent
     malicious claim even if the resource is deleted. Configure
     those where available.
   - **Monitor**: for nameserver or registrar-level risks, set up
     automated monitoring (cert-transparency-feed alerts, DNS-
     change monitoring).

## Payload Library

No payloads — passive enumeration. Key patterns:

- **CNAME → service**: table mapping known takeover-prone CNAME
  targets to their service providers and unclaimed signatures
- **HTTP unclaimed signatures**: per-service response-body
  patterns that indicate unclaimed state
- **NS takeover**: whois-based registration-availability checks

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-350 (Reliance on Reverse DNS Resolution — describes
  the trust-model issue). CWE-672 (Operation on a Resource after
  Expiration or Release — sometimes cited). For NS takeover,
  CWE-20 (Improper Input Validation at the DNS level).
- **OWASP**: WSTG-CONF-10. For APIs, API9:2023 (Improper
  Inventory Management). A05:2021 (Security Misconfiguration).
- **CVSS vectors**: typical takeover of a main-product subdomain
  (cookie-sharing with parent) —
  `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` (enables session
  hijack via shared cookies). Takeover of a subdomain that
  doesn't share cookies — `...C:L/I:L/A:N` (phishing potential
  only). NS takeover — `...S:C/C:H/I:H/A:H` (full zone control).
- **Evidence**: the `dig` output showing CNAME/NS target, the
  HTTP response with the unclaimed-service signature, AND for NS
  cases, the whois output for the expired parent domain.
- **Remediation framing**: platform / SRE engineer + DNS admin.
  Include:
  - Remove-dangling-record CLI snippets for the DNS provider
    (Route53: `aws route53 change-resource-record-sets`;
    Cloudflare: `cf api`)
  - Lifecycle-management checklist: delete DNS record BEFORE
    decommissioning the third-party resource
  - Per-service verification setup (AWS S3 `Conditions:
    StringEquals: aws:SourceAccount`, etc.)
  - DNS monitoring recommendation (e.g., dnstrails, SecurityTrails
    monitors, CT-log alerts)

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every subdomain in the inventory was resolved and
      classified (live / dangling / third-party)
- [ ] No subdomain was actually CLAIMED during testing (this
      skill detects only; claiming is a separate authorized
      action)
- [ ] Every finding cites the specific service-signature or
      whois evidence
- [ ] NS-record findings include the parent-domain whois output
- [ ] Recommendations distinguish "remove" vs "re-claim" vs
      "monitor" per finding
- [ ] Target-owned 404s are distinguished from third-party
      unclaimed signatures (Common Issues below)
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Target infrastructure 404 mistaken for service-unclaimed**:
  The target's own load balancer returns a generic "404 Not
  Found" for unknown hosts. That's not a takeover candidate —
  the server IS the target, not a third party. Distinguish by
  checking whether the HTTP response comes from the third-party
  infrastructure (match `Server` header or service-branded
  styles) vs the target's own.

- **Ownership-verification barriers**: Modern AWS (since ~2020)
  requires account-linked verification for custom-domain S3
  hosting. Similarly modern Heroku, Azure. A CNAME is dangling
  but the service prevents simple claim. Still file the finding
  — the dangling record is a misconfiguration — but note
  severity based on whether verification is enforced.

- **Internal / VPN-only subdomains**: A subdomain resolves only
  inside the corporate VPN. Public attackers can't reach it, so
  takeover has no impact. Confirm the subdomain is
  publicly reachable before filing as High.

- **Honeytoken subdomains**: Some orgs deliberately dangle
  subdomains with monitoring to detect attacker claims. Claiming
  them (if this skill were to — it doesn't) would trigger an
  alert. The detection is still useful — even if it's a
  honeypot, sharing it across the skills library reduces noise.

- **Service-provider false signatures**: Some service providers
  return the unclaimed signature for temporary-outage or
  rate-limit states, not just for actually-unclaimed resources.
  Verify with a second fetch 5-10 minutes later; if the
  signature disappears, it was transient.

- **Wildcard DNS**: `*.{target}` catch-all records respond to
  ANY subdomain with a legitimate page. Appears to prevent
  takeover (every subdomain "resolves"), but doesn't prevent
  attacker-chosen subdomain takeover of specific CNAME-targeted
  names. Note as "mitigated by wildcard but specific CNAMEs
  still dangling".

- **Outdated service documentation**: Some services change their
  unclaimed signatures without notice. If no signature matches
  but a CNAME looks dangling, note as "suspicious" and
  recommend the security team verify via a controlled
  claim-test in scope.

## References

External:
- WSTG-CONF-10: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover
- CWE-350: https://cwe.mitre.org/data/definitions/350.html
- EdOverflow's can-i-takeover-xyz signature list:
  https://github.com/EdOverflow/can-i-take-over-xyz
- HackerOne SubTake write-ups (historical case studies)

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia Técnico de Subdomain Takeover_ Detecção e Mitigação.md`

Grounded in:
- OWASP WSTG v4.2 (Section 4.2.10)
- Bug Bounty Bootcamp, Ch 20 (Subdomain Takeover)
- Bug Bounty Playbook V2 (Subdomain Takeover chapter)
- EdOverflow's "Can I take over XYZ?" research

Conversion date: 2026-04-24
Conversion prompt version: 1.0
