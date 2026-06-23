# web-check Check Catalog

Classification of every `lissy93/web-check` API endpoint used by this
skill: which tier it belongs to, what it touches, and the CWE/OWASP a
hygiene gap from it maps to. The runner (`run-webcheck.sh`) enforces the
tier split; this table is the rationale.

**Tier rule:** PASSIVE checks are third-party OSINT lookups or at most a
single benign unauthenticated GET / TLS handshake — safe under any
`testing_level >= passive`. ACTIVE checks send real probes or page load
to the target and require `testing_level: active` + `service_affecting:
approved`. OPT-IN checks reach a third party that performs a *fresh public
scan* and are off unless explicitly enabled.

## PASSIVE tier

| Check | What it does | Touches | Hygiene → CWE |
|---|---|---|---|
| `archives` | Wayback history | web.archive.org | — |
| `block-lists` | Domain/IP blocklist lookup | blocklist DBs | reputation |
| `carbon` | Page carbon estimate | websitecarbon.com | — |
| `cookies` | Reads Set-Cookie on one GET | target (1 GET) | CWE-1004 / CWE-614 |
| `dns` | A/AAAA/MX/NS records | DNS resolvers | — |
| `dns-server` | Resolver + DoH support | DNS | — |
| `dnssec` | DNSSEC record presence | DNS | CWE-350 |
| `get-ip` | Resolve host → IP | DNS | — |
| `headers` | Response headers on one GET | target (1 GET) | CWE-200 |
| `hsts` | HSTS preload eligibility | target / hstspreload | CWE-319 |
| `http-security` | CSP/XFO/XCTO/Referrer presence | target (1 GET) | CWE-693 / CWE-1021 |
| `location` | IP geolocation | geo DB (Google key) | — |
| `mail-config` | SPF/DKIM/DMARC/MX | DNS | email spoofing |
| `rank` | Global ranking | Tranco (key) | — |
| `redirects` | Redirect chain | target (GETs) | open-redirect hint |
| `robots-txt` | Fetch /robots.txt | target (1 GET) | disclosed paths |
| `security-txt` | Fetch /.well-known/security.txt | target (1 GET) | RFC-9116 |
| `shodan` | Host intel from Shodan DB | Shodan (key) | CWE-200 |
| `sitemap` | Fetch sitemap.xml | target (1 GET) | disclosed paths |
| `social-tags` | OpenGraph/meta tags | target (1 GET) | — |
| `ssl` | Cert + cipher (handshake) | target :443 | CWE-295 / CWE-327 |
| `status` | Up/down + timing | target (1 GET) | — |
| `subdomains` | Passive subdomain enum | SecurityTrails (key) | API9 asset mgmt |
| `tech-stack` | Wappalyzer fingerprint | target (1 GET) | CWE-200 |
| `threats` | Threat-intel reputation | threat DBs | reputation |
| `tls-connection` | Negotiated protocol/cipher | target :443 | CWE-326 / CWE-327 |
| `txt-records` | TXT records | DNS | — |
| `whois` | Registration data | WHOIS | — |

## ACTIVE tier (testing_level: active + service_affecting: approved)

| Check | What it does | Why active | Hygiene → CWE |
|---|---|---|---|
| `ports` | Port scan of common ports | sends probes to many ports | CWE-200 |
| `trace-route` | Network path to host | emits trace packets | — |
| `firewall` | WAF detection | sends crafted test requests | CWE-693 |
| `linked-pages` | Crawls internal/external links | many GETs | surface |
| `quality` | Lighthouse audit | full page load + audit (heavy) | — |
| `screenshot` | Headless-Chromium capture | renders + runs page JS | — |

## OPT-IN (off by default — `INCLUDE_TLS_LABS=1`)

| Check | What it does | Why gated |
|---|---|---|
| `tls-labs` | Qualys SSL Labs scan | runs a **fresh public scan** of the host; results may be publicly listed. Enable only when scope approves third-party public scanning. |

## Notes

- Third-party-backed checks (`shodan`, `subdomains`, `rank`, `location`,
  some `archives`) return empty without an API key in `.env`. Empty ≠
  clean — the normalizer labels these "no key configured".
- `ssl` / `tls-connection` perform a TLS handshake only (no payload); they
  are treated as passive, consistent with `web-recon-passive`'s on-site
  signal collection.
- Every escalation from this skill except expired/invalid-TLS and leaked
  credentials stays **Suspected/Informational** — hand to the owning
  hunter, don't inflate.
