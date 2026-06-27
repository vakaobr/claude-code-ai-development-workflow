---
name: web-check-recon
description: "Runs a self-hosted web-check (lissy93/web-check) instance to collect 30+ structured recon signals for an in-scope host — TLS/SSL posture, DNS/DNSSEC/TXT, security headers, cookies, redirects, tech-stack, subdomains, mail config (SPF/DKIM/DMARC), blocklist/threat reputation, WHOIS, archives, and (active tier only) port scan, traceroute, WAF probe, link crawl and screenshot. Spins the container up on demand via a managed docker compose, calls the JSON API per the asset's testing_level, normalizes results into PASSIVE_RECON.md / WEBCHECK.md, and proposes hygiene findings for analyst review. Use as a fast first-pass that augments web-recon-passive and feeds attack-surface-mapper and the hunters. Defensive testing only, against assets listed in .claude/security-scope.yaml."
model: sonnet
# Profile: recon-webcheck (see _shared/tool-profiles.md) — the `active` recon
# profile, narrowed to this skill's needs, plus on-demand container lifecycle:
#   - Bash(docker:compose*) / Bash(docker:ps|inspect*) to manage the local
#     web-check container (human-approved extension, see commit message).
#   - Bash(curl:*) is restricted by methodology to 127.0.0.1:3000 (the local
#     API) — the only outbound prober is web-check itself, which the scope
#     gate constrains. No direct curl to targets.
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  WebFetch,
  Bash(docker:compose*), Bash(docker:ps*), Bash(docker:inspect*),
  Bash(docker:logs*),
  Bash(bash:*), Bash(python3:*),
  Bash(curl:*), Bash(jq:*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: recon
  authorization_required: true
  tier: T4
  source_methodology: "lissy93/web-check (MIT) — OSINT/recon aggregator"
  service_affecting: true
  composed_from: []
---

# Web-Check Recon

## Goal

Collect a broad, structured first-pass of recon signals for an in-scope
host using a **self-hosted** [web-check](https://github.com/lissy93/web-check)
instance, normalize the JSON output into the assessment's existing recon
dossier, and surface configuration-hygiene gaps for the analyst to
confirm.

This skill is an **enumerator**, not a vulnerability scanner. It produces
no confirmed findings on its own (except clearly-exploitable disclosures
such as leaked credentials). Its value is speed and breadth: in one pass
it fills most of the `PASSIVE_RECON.md` fingerprint, DNS, TLS, headers,
cookies, subdomain, and reputation sections that `web-recon-passive`
otherwise gathers tool-by-tool — freeing the manual passive skill to
focus on the OSINT depth web-check does not do (GitHub secret dorks,
file-metadata pulls, Wayback parameter mining).

Its output feeds `attack-surface-mapper`, the class-specific hunters, and
the `security-analyst` / Shannon validation phase.

## When to Use

- As the **first** step of the recon phase, before or alongside
  `web-recon-passive`, to get structured TLS/DNS/headers/cookies/tech
  coverage quickly.
- When you want a repeatable, parseable snapshot of a host's externally
  observable posture (re-run later to diff configuration drift).
- When the orchestrator's phase-0 plan asks for a fast inventory before
  deciding which hunters to dispatch.
- When self-hosting matters — you must NOT submit a client target to the
  public `web-check.xyz` instance (scope/RoE: it discloses the target to
  a third party and probes from an IP you don't control).

## When NOT to Use

- For deep active surface mapping (directory brute-force, hidden-param
  discovery, HTTP-method enumeration) — that's `web-recon-active`.
- For API-spec enumeration (OpenAPI/Swagger/GraphQL introspection) —
  that's `api-recon`.
- For OSINT requiring credential/secret discovery in public code — that's
  `web-recon-passive` Phase 4 + `secrets-in-code-hunter`.
- For confirming/exploiting any signal this skill surfaces — hand the
  candidate to the relevant hunter and the analyst.
- Any asset not listed in `.claude/security-scope.yaml`.

## Authorization Check (MANDATORY FIRST STEP)

Before bringing the container up or issuing ANY check:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist, is a
   placeholder template, or doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list and note its
   `testing_level` and `service_affecting` fields.
3. **Select the check tier from the scope, never from convenience:**
   - `testing_level: passive` (or production `passive_only`) → run the
     **PASSIVE** check set only. These are third-party OSINT lookups plus
     at most a single benign unauthenticated GET / TLS handshake per
     check — equivalent to `web-recon-passive`'s on-site signals.
   - `testing_level: active` → PASSIVE set **plus** the ACTIVE set
     (`ports`, `trace-route`, `firewall`, `linked-pages`, `quality`,
     `screenshot`). These send real probes/load to the target, so they
     require `service_affecting: approved`. If `service_affecting:
     denied`, run PASSIVE only and note the active checks were skipped.
   - `testing_level: none` → halt; do not test.
4. `tls-labs` submits the host to Qualys SSL Labs for a **fresh public
   scan** (results may be publicly listed). It is OFF by default. Only
   enable it (`INCLUDE_TLS_LABS=1`) when the scope notes third-party
   public scanning is acceptable for the asset.
5. Apply the scope's `rate_limit_rps`. web-check is configured with
   `API_ENABLE_RATE_LIMIT=true` and a per-check timeout; the runner also
   spaces requests. Honor per-environment overrides (production ~5 rps).
6. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with
   status `running`, recording the asset, the tier selected, and whether
   `tls-labs` was enabled.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from `security-scope.yaml` (hostname)
- `{tier}`: optional override — `passive` | `active`. If omitted, derive
  from the asset's `testing_level` per the Authorization Check. A caller
  may only *narrow* the tier, never widen it past the scope.
- `{api_keys}`: optional — path to an `.env` file supplying keys for the
  third-party-backed checks (`SHODAN_API_KEY`, `SECURITY_TRAILS_API_KEY`,
  `GOOGLE_CLOUD_API_KEY`, etc.). Without them, those checks degrade
  gracefully (return empty/limited data, not an error).

## Methodology

All commands run from the skill directory
`.claude/skills/web-check-recon/`. The scripts are dependency-light
(bash + curl + python3 stdlib); `jq` is optional and only used for
pretty-printing.

### Phase 1: Run the full collection pipeline (one command)

1. **After the Authorization Check has set `{target}` and `{tier}`, run
   the one-shot driver.** It performs the entire collection pipeline —
   image pull (idempotent) → container up (health-gated) → all tier
   checks → normalize → teardown — so there is nothing to run by hand
   and no step to forget:

   ```bash
   bash scripts/recon.sh {target} {tier} .claude/planning/{issue}
   ```

   Options (all default-safe): `--keep-up` (leave the container running
   for a follow-up run), `--tls-labs` (only with scope approval — see
   Authorization step 4), `--rps N` (match the scope rate limit),
   `--no-pull` (offline / already pulled).

   What the driver does, in order:
   - **Pull** `lissy93/web-check` once (≈1 GB, includes Chromium) via
     `docker compose pull` — no-op if already cached.
   - **Up** via `docker compose -p web-check-recon up -d` against the
     bundled hardened `docker-compose.yml` (port bound to **127.0.0.1
     only**, `DISABLE_GUI=true`, rate-limit on, bounded timeout), then
     polls `http://127.0.0.1:3000/api/status` until healthy.
   - **Run** the scope-appropriate check set, one `{check}.json` per
     check under `.claude/planning/{issue}/webcheck/raw/`; non-200s are
     saved as `{check}.error.txt` rather than aborting the run.
     - **PASSIVE set** (always): `archives`, `block-lists`, `carbon`,
       `cookies`, `dns`, `dns-server`, `dnssec`, `get-ip`, `headers`,
       `hsts`, `http-security`, `location`, `mail-config`, `rank`,
       `redirects`, `robots-txt`, `security-txt`, `shodan`, `sitemap`,
       `social-tags`, `ssl`, `status`, `subdomains`, `tech-stack`,
       `threats`, `tls-connection`, `txt-records`, `whois`
     - **ACTIVE set** (only when `{tier}` == active): `ports`,
       `trace-route`, `firewall`, `linked-pages`, `quality`, `screenshot`
     - **OPT-IN**: `tls-labs` (only with `--tls-labs`)
   - **Normalize** the raw JSON into the assessment artifacts:
     - `WEBCHECK.md` — full structured snapshot (every check, grouped).
     - `PASSIVE_RECON.patch.md` — append-ready blocks mapped onto the
       `web-recon-passive` dossier sections (Subdomains, Tech
       Fingerprint, Metafiles).
     - `webcheck/findings-candidates.md` — proposed hygiene findings in
       the canonical schema, each marked **Suspected**, for analyst
       review before appending to `SECURITY_AUDIT.md`.
   - **Down** via `docker compose -p web-check-recon down` (skipped with
     `--keep-up`).

   See `references/check-catalog.md` for the full per-check
   classification, third-party touchpoints, and CWE mapping.

   **Manual / debugging.** The pipeline is also available as discrete
   steps when you need them: `scripts/webcheck-up.sh {pull|up|down|
   status|logs}`, `scripts/run-webcheck.sh {target} {tier} {raw_dir}`,
   and `scripts/normalize.py --raw {raw_dir} --target {target} --out
   {planning_dir}`. The driver simply chains these.

### Phase 2: Merge, escalate, confirm teardown

2. **Merge into `PASSIVE_RECON.md`.** If the dossier exists, fold the
   `PASSIVE_RECON.patch.md` blocks into the matching sections (don't
   clobber existing manual OSINT — append and de-duplicate). If it
   doesn't exist yet, note that `web-recon-passive` should consume
   `WEBCHECK.md` when it runs.

3. **Escalate only what's clearly real.** Review
   `findings-candidates.md`. Append to `SECURITY_AUDIT.md` (with the
   `.audit.lock` held, monotonic IDs, per `_shared/finding-schema.md`)
   ONLY findings that stand on their own as recon-level facts:
   - Expired / not-yet-valid / self-signed certificate, or deprecated
     TLS protocol enabled → confirmable from the handshake.
   - Plaintext-only service (no HTTPS / no HSTS with sensitive flows).
   - Leaked credential or secret surfaced in any check → **High**,
     immediate, cross-ref `secrets-in-code-hunter`.
   Everything else (missing CSP, cookie flags, missing security.txt,
   DNSSEC off, SPF/DMARC gaps, reputation hits, version disclosure) stays
   as **Suspected/Informational** candidates handed to the relevant
   hunter (`clickjacking-hunter`, `session-flaw-hunter`,
   `crypto-flaw-hunter`, `csrf-hunter`) — do not inflate severity.

4. **Confirm teardown.** The driver tears the container down on exit
   unless `--keep-up` was passed. Verify with
   `bash scripts/webcheck-up.sh status` (expect `DOWN`); the image is
   kept for the next run unless the operator prunes it.

## Payload Library

No exploit payloads — this is reconnaissance. The only "probe patterns"
are the web-check API calls, all of GET form:

```
GET http://127.0.0.1:3000/api/{check}?url=https://{target}
```

Tier membership and third-party touchpoints are catalogued in
`references/check-catalog.md`.

## Output Format

This skill's primary outputs are **inventory artifacts**, not findings:

- `.claude/planning/{issue}/WEBCHECK.md` — full structured snapshot.
- `.claude/planning/{issue}/PASSIVE_RECON.patch.md` — blocks to merge
  into the `web-recon-passive` dossier.
- `.claude/planning/{issue}/webcheck/raw/*.json` — raw per-check output
  (kept for evidence / diffing).
- `.claude/planning/{issue}/webcheck/findings-candidates.md` — proposed
  findings for analyst triage.

It appends to `SECURITY_AUDIT.md` ONLY for self-standing recon facts
(per `_shared/finding-schema.md`), e.g.:

- **Expired / invalid / weak-protocol TLS** → CWE-295 / CWE-326 / CWE-327,
  severity Medium (High if it breaks confidentiality of a sensitive flow).
- **Sensitive flow served over plaintext / no HSTS** → CWE-319, Medium.
- **Leaked credential/secret in any check output** → CWE-798, High,
  immediate, with rotation request.

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security.
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log.

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] The tier run matches the asset's `testing_level` in the scope file
      (PASSIVE-only when not `active`; ACTIVE only with
      `service_affecting: approved`).
- [ ] `tls-labs` was run ONLY if explicitly enabled for this asset.
- [ ] Every check that targeted a host confirms that host is in scope
      (grep the raw output dir against the scope asset list).
- [ ] The container was bound to 127.0.0.1 (not exposed publicly) and was
      torn down after the run.
- [ ] No client target was ever sent to the public web-check instance.
- [ ] Candidate findings are marked Suspected; only self-standing recon
      facts were promoted into `SECURITY_AUDIT.md` (no severity
      inflation).
- [ ] Any leaked credential is filed immediately and cross-referenced to
      `secrets-in-code-hunter`.
- [ ] Cross-references to `web-recon-passive`, `web-recon-active`,
      `api-recon`, and `attack-surface-mapper` are noted so follow-up
      skills don't duplicate work.
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`.

## Common Issues

- **Container pull is large.** First `up` pulls ~1 GB (bundles Chromium
  for the screenshot/quality checks). Pre-pull during setup so a live
  assessment isn't waiting on a download.

- **Third-party-backed checks return empty without keys.** `shodan`,
  `subdomains` (SecurityTrails), `location`/`rank` (Google/Tranco) need
  API keys via the `.env` file. Missing keys yield empty data, not
  errors — note "no key configured" in `WEBCHECK.md` rather than
  reporting "clean".

- **CDN/WAF in front of production.** As with all external recon, headers,
  TLS, and IP reflect the edge, not the origin. Mark CDN-terminated
  results so downstream skills interpret them correctly.

- **`tls-labs` is public.** It is OFF by default precisely because it can
  publish a scan of the client's host. Never enable it for an asset
  without explicit scope approval.

- **`screenshot`/`quality`/`linked-pages` execute the page.** They load
  the target in headless Chromium and can trigger client-side analytics
  or state changes. They live in the ACTIVE tier for this reason — never
  run them under a passive scope.

- **Hygiene ≠ vulnerability.** A missing CSP or an absent `security.txt`
  is a hardening gap, not an exploitable finding. Keep these as
  Informational candidates; let the hunter that owns the class decide if
  there's a real, exploitable issue.

## References

External:
- web-check (lissy93/web-check, MIT): https://github.com/lissy93/web-check
- WSTG-INFO family: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/
- Mozilla Web Security guidelines (headers/cookies/TLS): https://infosec.mozilla.org/guidelines/web_security
- CWE: https://cwe.mitre.org/

Internal:
- `references/check-catalog.md` — per-check tier, third-party, CWE map.
- `_shared/finding-schema.md` — canonical finding format.
- `_shared/tool-profiles.md` — the `recon-webcheck` profile.
- Cross-references: `web-recon-passive`, `web-recon-active`, `api-recon`,
  `attack-surface-mapper`.

## Source Methodology

Wraps the open-source `lissy93/web-check` (MIT-licensed) OSINT aggregator
as a scope-gated, self-hosted recon feeder for this stack. web-check
performs the data collection; this skill supplies the authorization gate,
tier selection, normalization into the assessment dossier, and the
escalation discipline the rest of the security skills expect.

Integration date: 2026-06-23
Conversion prompt version: 1.0
