# Security Skills Library

39 defensive security-testing skills plus the `security-orchestrator`
agent that composes them. Skills are under `.claude/skills/{name}/`;
the agent is at `.claude/agents/security-orchestrator.md`; the
authorization file is `.claude/security-scope.yaml` (template — must be
populated with real company assets before any live use).

## Quickstart

1. **Populate the scope file.** Edit `.claude/security-scope.yaml` with
   real company-owned assets, test credentials vault paths, and an
   authorized OOB listener host. Every skill halts if the scope file
   contains only placeholder values.
2. **Run discovery.** `/discover Security assessment of {asset}` creates
   a planning folder at `.claude/planning/{issue-name}/`.
3. **Dispatch the orchestrator.** `@security-orchestrator {issue-name}`
   selects + runs the appropriate hunter skills based on asset type and
   scope. The orchestrator produces `07a_SECURITY_AUDIT.md`.
4. **Alternative (small scope).** `/security {issue-name}` delegates to
   the orchestrator for large/high-risk scopes and falls back to the
   OWASP/STRIDE checklist for M-sized features.

## Skill inventory (39 skills)

### Tier 4 — Recon / Foundation (5 skills)
Run before any hunter. Produce inventory artifacts that hunters consume.

| Skill | Profile | Output |
|---|---|---|
| [web-recon-passive](web-recon-passive/SKILL.md) | passive | `PASSIVE_RECON.md` |
| [web-recon-active](web-recon-active/SKILL.md) | active | `ATTACK_SURFACE.md` |
| [api-recon](api-recon/SKILL.md) | active | `API_INVENTORY.md` |
| [auth-flow-mapper](auth-flow-mapper/SKILL.md) | passive | `AUTH_FLOWS.md` |
| [attack-surface-mapper](attack-surface-mapper/SKILL.md) | active | `CONSOLIDATED_ATTACK_SURFACE.md` |

### Tier 1/2 — Authentication (4 skills)

| Skill | Profile | Covers |
|---|---|---|
| [auth-flaw-hunter](auth-flaw-hunter/SKILL.md) | active | Enumeration, lockout, MFA-skip, default creds, alt-channel drift |
| [session-flaw-hunter](session-flaw-hunter/SKILL.md) | active | Entropy, fixation, cookie flags, logout invalidation, token tampering |
| [jwt-hunter](jwt-hunter/SKILL.md) | active | `alg:none`, HS256 cracking, RS256→HS256 confusion, `kid`/`jku` injection |
| [oauth-oidc-hunter](oauth-oidc-hunter/SKILL.md) | active | redirect-URI validation, state/CSRF, code reuse, flow downgrade |

### Tier 1 — Access Control (2 skills)

| Skill | Profile | Covers |
|---|---|---|
| [idor-hunter](idor-hunter/SKILL.md) | active | Web-app object-ID authorization (CWE-639) |
| [bola-bfla-hunter](bola-bfla-hunter/SKILL.md) | active | API BOLA (API1:2023) + BFLA (API5:2023) |

### Tier 1/2 — Injection (6 skills)

| Skill | Profile | Covers |
|---|---|---|
| [sqli-hunter](sqli-hunter/SKILL.md) | active | Error/Boolean/time/UNION-based SQLi, auth bypass |
| [xxe-hunter](xxe-hunter/SKILL.md) | active | In-band file read, SSRF, blind OOB, XInclude, SVG/OXML |
| [ssti-hunter](ssti-hunter/SKILL.md) | active | Jinja2/Twig/Freemarker/ERB/Velocity/Tornado/Handlebars RCE |
| [command-injection-hunter](command-injection-hunter/SKILL.md) | active | Separator injection, blind time-based/OOB, shell-escape bypass |
| [path-traversal-hunter](path-traversal-hunter/SKILL.md) | active | `../` traversal, LFI, RFI, encoding bypasses, protocol wrappers |
| [deserialization-hunter](deserialization-hunter/SKILL.md) | active | PHP / Java / Python pickle / Ruby Marshal / YAML gadget chains |

### Tier 1/2 — Client-side (6 skills)

| Skill | Profile | Covers |
|---|---|---|
| [xss-hunter](xss-hunter/SKILL.md) | active | Reflected + Stored XSS, context-aware payloads |
| [dom-xss-hunter](dom-xss-hunter/SKILL.md) | active | Source→sink DOM-XSS, postMessage, framework-specific |
| [clickjacking-hunter](clickjacking-hunter/SKILL.md) | passive | XFO / CSP `frame-ancestors` / `SameSite` / UI-redress |
| [csrf-hunter](csrf-hunter/SKILL.md) | active | Token absence, method-swap, Referer bypass, SameSite gaps |
| [open-redirect-hunter](open-redirect-hunter/SKILL.md) | active | Protocol-relative / path-prefix / userinfo / encoding bypasses |
| [cors-misconfig-hunter](cors-misconfig-hunter/SKILL.md) | passive | Origin-reflection + credentials, `null` origin, subdomain confusion |

### Tier 1/2 — API-class (5 skills)

| Skill | Profile | Covers |
|---|---|---|
| [graphql-hunter](graphql-hunter/SKILL.md) | active | Introspection, BOLA via relay IDs, depth DoS, batching, scalar fuzz |
| [mass-assignment-hunter](mass-assignment-hunter/SKILL.md) | active | Blind property injection, HPP, method-swap-with-MA |
| [excessive-data-exposure-hunter](excessive-data-exposure-hunter/SKILL.md) | active | Over-exposing fields, JS-bundle secrets, debug params, error leaks |
| [rate-limit-hunter](rate-limit-hunter/SKILL.md) | active (service_affecting) | Auth brute-force, MFA brute-force, SMS cost amplification, payload stress |
| [owasp-api-top10-tester](owasp-api-top10-tester/SKILL.md) | active | Orchestration: dispatches 8 sub-hunters + produces `API_TOP10_COVERAGE.md` |

### Tier 1/2 — Server-side (3 skills)

| Skill | Profile | Covers |
|---|---|---|
| [ssrf-hunter](ssrf-hunter/SKILL.md) | active | Loopback, internal-IP, cloud metadata, protocol smuggling, DNS rebinding |
| [ssrf-cloud-metadata-hunter](ssrf-cloud-metadata-hunter/SKILL.md) | active | AWS IMDSv1/v2 bypass, GCP v1beta1, Azure metadata — downstream of SSRF |
| [cache-smuggling-hunter](cache-smuggling-hunter/SKILL.md) | active (staging-only, dual-gated) | Cache poisoning via unkeyed headers, CL.TE / TE.CL smuggling |

### Tier 1 — Logic + Cross-cutting (2 skills)

| Skill | Profile | Covers |
|---|---|---|
| [business-logic-hunter](business-logic-hunter/SKILL.md) | active | Workflow bypasses, logical-invalid data, hidden-field tampering, one-time-function reuse |
| [crypto-flaw-hunter](crypto-flaw-hunter/SKILL.md) | passive | Consolidates TLS / cookie / JWT / secret artifacts into `CRYPTO_POSTURE.md` |

### Tier 3 — Cloud / CI/CD / Secrets (5 skills)

| Skill | Profile | Covers |
|---|---|---|
| [aws-iam-hunter](aws-iam-hunter/SKILL.md) | cloud-readonly | Over-privileged roles, exposed keys, IMDSv1, dangling DNS, leaky ARNs |
| [s3-misconfig-hunter](s3-misconfig-hunter/SKILL.md) | cloud-readonly | Public ACLs / policies, missing Block-Public-Access, SSE / versioning / logging gaps |
| [container-hunter](container-hunter/SKILL.md) | cloud-readonly | Privileged pods, permissive SecurityContexts, RBAC, missing NetworkPolicies, Dockerfile anti-patterns |
| [gitlab-cicd-hunter](gitlab-cicd-hunter/SKILL.md) | cicd-readonly | Pipeline secrets, `.git/` leaks, webhook SSRF, privileged runners |
| [secrets-in-code-hunter](secrets-in-code-hunter/SKILL.md) | repo-readonly | trufflehog + gitleaks + custom regex over repo history |

### Tier 2 — Recon-adjacent (1 skill)

| Skill | Profile | Covers |
|---|---|---|
| [subdomain-takeover-hunter](subdomain-takeover-hunter/SKILL.md) | passive | Dangling CNAMEs to unclaimed GitHub / S3 / Heroku / Azure; NS takeover |

## Tool profiles

All skills reference one of 5 profiles defined in
[_shared/tool-profiles.md](_shared/tool-profiles.md):

- **passive** — `Read, Grep, Glob, WebFetch` (no Bash outside planning/)
- **active** — passive + allowlisted Bash (`curl`, `ffuf`, `nuclei`,
  `arjun`, `nmap --script=safe`, etc.; forbidden: sqlmap, metasploit,
  hydra, nikto)
- **cloud-readonly** — passive + `aws` CLI restricted to `describe-*`,
  `get-*`, `list-*`, `simulate-principal-policy` (no write verbs)
- **cicd-readonly** — passive + `glab` restricted to read-only +
  `git log/show/blame/grep`
- **repo-readonly** — passive + `git log/show/blame/grep/diff` +
  `trufflehog`, `gitleaks detect/protect`

## Output contract

All skills append findings to a single canonical file:
`.claude/planning/{issue}/07a_SECURITY_AUDIT.md` using the schema in
[_shared/finding-schema.md](_shared/finding-schema.md). Monotonic
`FINDING-NNN` IDs, append-only, per-finding CWE / OWASP / CVSS +
evidence + remediation.

## Cross-skill dispatch patterns

- `ssrf-hunter` → `ssrf-cloud-metadata-hunter` → `aws-iam-hunter`
  (SSRF confirmed → IMDS probe → IAM enumeration). Each skill stops
  at its boundary.
- `auth-flow-mapper` → `jwt-hunter` / `oauth-oidc-hunter` /
  `session-flaw-hunter` / `auth-flaw-hunter` (mapper produces
  `AUTH_FLOWS.md` + handoff files).
- `graphql-hunter` → `sqli-hunter` / `command-injection-hunter` (for
  resolver-bound injection candidates).
- `owasp-api-top10-tester` dispatches 8 sub-hunters and produces
  `API_TOP10_COVERAGE.md`.
- `open-redirect-hunter` → `oauth-oidc-hunter` (feeds OAuth-chain
  candidates).
- `secrets-in-code-hunter` → `aws-iam-hunter` (AWS-key validation
  handoff; keys stored as `first4…last4…sha256` hash only).

## Validation

```bash
./scripts/validate-skills.sh
```

Checks: file presence, frontmatter fields, required sections, name
matches directory, description length, scope-file reference,
defensive-framing heuristic, forbidden-tool catch, cloud-readonly
write-verb catch, references/ file consistency.

Expected output: **0 errors, 0 warnings** across 39 skills.

## Authorization model

Summary (full contract in project `CLAUDE.md` > "Security Testing
Scope and Authorization"):

1. Every skill reads `.claude/security-scope.yaml` before outbound
   activity.
2. No testing outside declared `assets`.
3. No destructive payloads without `destructive_testing: approved`
   per asset.
4. OOB listeners must be in scope's allowlist.
5. RCE / credential-theft confirmations STOP at proof — no pivoting.
6. Append-only findings in `SECURITY_AUDIT.md` via the canonical
   schema.
