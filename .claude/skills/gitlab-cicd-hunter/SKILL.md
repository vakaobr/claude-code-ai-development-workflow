---
name: gitlab-cicd-hunter
description: "Audits GitLab repositories and CI/CD pipelines for exposed secrets in commit history / issues / MRs, insecure `.gitlab-ci.yml` patterns (hardcoded vars, privileged runners, Docker-socket mounts), webhook SSRF, reachable `.git/` directories, and `.bash_history` leaks on misconfigured hosts. Use when the target organization uses GitLab for SCM and/or CI/CD; after `web-recon-passive` surfaces repo references; or when the orchestrator identifies `gitlab.*` subdomains. Produces findings with CWE-798 / CWE-522 / CWE-918 mapping and pipeline-hardening remediation. Defensive testing only, READ-ONLY GitLab API calls."
model: opus
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  Bash(glab:repo*), Bash(glab:ci list*), Bash(glab:ci view*),
  Bash(glab:ci trace*), Bash(glab:mr list*), Bash(glab:mr view*),
  Bash(glab:issue list*), Bash(glab:issue view*),
  Bash(git:log*), Bash(git:show*), Bash(git:blame*), Bash(git:grep*),
  Bash(yq:*), Bash(jq:*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: cicd
  authorization_required: true
  tier: T3
  source_methodology: "Guia de Segurança e Auditoria em Pipelines CI_CD GitLab.md"
  service_affecting: false
  composed_from: []
---

# GitLab CI/CD Hunter

## Goal

Audit the organization's GitLab instance and CI/CD pipelines for
exposures that turn SCM or build infrastructure into a credential
source or pivot point: secrets committed to repos / issues / MRs,
insecure `.gitlab-ci.yml` patterns, privileged runners, webhook-
SSRF vectors, reachable `.git/` directories on production, and
`.bash_history` on misconfigured hosts. This skill implements WSTG-
CONF-02 adjacencies and maps findings to CWE-798 (hard-coded
credentials), CWE-522 (insufficiently protected credentials), and
CWE-918 (SSRF) for webhook cases. The goal is to give platform and
security teams a concrete list of exposures with exact file/line
references and vault-migration remediation.

## When to Use

- The target organization uses GitLab (self-hosted or SaaS) for
  source-control AND/OR runs pipelines via GitLab CI.
- Passive recon (`web-recon-passive`) surfaced public GitLab repos,
  commits, MRs, or issues for the org.
- The scope file lists a `gitlab.*` subdomain as in-scope.
- `web-recon-active` found a reachable `.git/` directory on a
  production host.
- The orchestrator selects this skill after detecting pipeline-
  related assets.

## When NOT to Use

- For general code-wide secret hunting (non-CI/CD, non-GitLab) —
  use `secrets-in-code-hunter`, which has broader scope and
  trufflehog/gitleaks integration.
- For GitHub Actions / Bitbucket Pipelines / CircleCI — those need
  a platform-specific skill (not written yet — file a gap in
  `references/gaps.md`).
- For AWS IAM posture on pipelines that authenticate to AWS — this
  skill flags the pipeline config leak; `aws-iam-hunter` validates
  any discovered keys and enumerates their permissions.
- For webhook SSRF testing against arbitrary endpoints — use
  `ssrf-hunter`; this skill's webhook testing is scoped to CI/CD
  trigger URLs only.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not at least `passive`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or
   doesn't parse, halt and report.
2. Confirm the GitLab host (e.g., `gitlab.internal.example.com`)
   appears in the `assets` list AND its `testing_level` is at least
   `passive`. This skill uses read-only `glab` commands — workloads
   are not touched — so passive is acceptable.
3. Confirm the `glab` CLI is configured with a read-only audit
   token, NOT a developer's personal token. Run `glab auth status`
   and log the principal. Halt if the token has `api` scope but
   the audit should be `read_api` only.
4. Do NOT trigger pipeline runs. `glab ci run`, `glab pipeline run`,
   and `glab mr merge` are blocked by the tool profile; this skill
   must not attempt to bypass.
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with
   status `running`. Include the GitLab host and audit-token
   principal.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier (GitLab host)
- `{org}`: the GitLab group/namespace to audit
- `{glab_profile}`: named glab config profile with the audit token
- `{focus_repos}`: optional — specific repos to prioritize
- `{oob_listener}`: optional — authorized OOB listener for webhook
  SSRF testing (only if scope explicitly permits)

## Methodology

### Phase 1: Repository Secret Exposure

1. **Enumerate accessible repos + default branches** [Hacking APIs, Ch 6, p. 230]

   Do: `glab repo list --owner {org} --per-page 100` — list every
   repo visible to the audit token. Record project paths, default
   branches, visibility (public/internal/private), and last activity.

   Record: `.claude/planning/{issue}/gitlab-audit/repo-inventory.md`.

2. **Grep for secrets in repo contents** [Bug Bounty Bootcamp, Ch 5, p. 67]

   Do: For each repo, clone (read-only) and scan:
   ```bash
   git grep -nE "(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z-]+|AWSS3AccessKeyID|password\s*[:=]\s*['\"][^'\"]{8,}|BEGIN (RSA|DSA|EC) PRIVATE KEY|api[_-]?key\s*[:=]\s*['\"][^'\"]{16,})" HEAD
   ```

   Expand the regex with trufflehog/gitleaks signatures where
   available (use the `secrets-in-code-hunter` skill's references
   for the canonical list).

   Vulnerable response: Hit on HEAD or in git history.

   Record: Each hit in `gitlab-audit/repo-secrets.md` with repo,
   file, line, commit SHA, and a HASH of the secret value (NEVER
   store plaintext).

3. **Scan issue and MR bodies + comments** [Hacking APIs, Ch 6]

   Do: `glab issue list --state=all --repo {repo}` and `glab mr
   list --state=all --repo {repo}` for each repo. For each item,
   fetch the body + comments and run the secret regex above.

   Vulnerable response: Credentials pasted into a debug comment or
   MR description.

   Record: Per-hit entry in `gitlab-audit/issue-mr-secrets.md`.

### Phase 2: Pipeline Configuration Audit

4. **Extract and parse every `.gitlab-ci.yml`** [OWASP API7:2019]

   Do: For each repo, `git show HEAD:.gitlab-ci.yml 2>/dev/null |
   yq eval '.' -` (use yq to normalize YAML). Also check for
   `.gitlab/ci/*.yml` includes.

   Flag the following patterns:
   - `variables:` with values that look like secrets (API keys,
     passwords, URLs with embedded creds)
   - `services:` using privileged containers without isolation
   - `image:` pinned to a moving tag (`latest`, `stable`) — supply
     chain risk
   - `before_script` / `script` echoing `$SECRET_VAR` to logs
   - `artifacts:` publishing `.env`, `config.json`, or similar

   Record: Pipeline-config findings in
   `gitlab-audit/pipeline-configs.md`.

5. **Check runner registration posture**
   [Bug Bounty Bootcamp, Ch 21, p. 328]

   Do: `glab runner list --group {org}` (if audit-token allows).
   Flag runners that:
   - Are shared across untrusted projects
   - Use `privileged = true` in their Docker executor config
   - Mount `/var/run/docker.sock` from host (escape vector)
   - Are on self-hosted infrastructure without network isolation

   Record: Per-runner entry in `gitlab-audit/runners.md`.

### Phase 3: Exposed `.git/` Directories on Production

6. **Probe production hosts for `/.git/` leakage** [Bug Bounty Bootcamp, Ch 21, p. 331]

   Do: For each production host in scope, test:
   ```
   /.git/HEAD
   /.git/config
   /.git/index
   /.git/logs/HEAD
   /.git/refs/heads/main
   ```

   Use only `curl` (part of `active` profile) — this skill's
   profile allows it for external HTTP checks. If this skill's
   profile is strict cicd-readonly without curl, delegate to
   `web-recon-active`'s output.

   Vulnerable response: Any of these paths returns 200 with Git
   object content — the production host leaks the entire repo
   history. Tooling like `git-dumper` could reconstruct the
   codebase.

   Record: FINDING-NNN per host, Critical severity if the repo
   history contains production credentials.

### Phase 4: Webhook SSRF Testing (Gated)

7. **Inventory webhook-capable endpoints** [zseano's methodology, p. 1043]

   Do: `glab api "projects/{repo}/hooks"` and
   `glab api "groups/{org}/hooks"` to enumerate webhooks. List
   their URLs — are they pointing at internal-only systems?

   Record: Webhook inventory in `gitlab-audit/webhooks.md`.

8. **SSRF probing via webhook URL field (if scope permits)**
   [zseano's methodology, p. 1043]

   Do: ONLY if the scope file explicitly lists
   `webhook_ssrf_testing: approved`: attempt to create a test
   webhook pointing at the authorized OOB listener, trigger a
   pipeline event (if the audit role allows), and observe whether
   the listener receives a connection.

   Default: skip this step if scope doesn't explicitly approve. A
   webhook inventory alone is already a finding if URLs point at
   sensitive internal systems.

### Phase 5: `.bash_history` and DevOps-Artifact Leaks

9. **Probe production hosts for `.bash_history` on web root**
   [OWASP API7:2019, p. 843]

   Do: For each production host, test common paths:
   ```
   /.bash_history
   /~{deploy_user}/.bash_history
   /home/{deploy_user}/.bash_history
   /admin/.bash_history
   /backup/.bash_history
   ```

   Vulnerable response: File contents returned containing shell
   commands with API credentials (`curl ... -H "Authorization:
   Bearer XXXX"`, `aws s3 cp s3://... --profile prod`).

   Record: FINDING-NNN per leaked history file. Pair with
   `secrets-in-code-hunter` if shell history reveals valid API
   tokens.

### Phase 6: `.well-known/security.txt` Presence

10. **Check for security.txt** [WSTG v4.2]

    Do: `curl -s https://{target}/.well-known/security.txt`.

    Vulnerable condition: File absent (best-practice gap, not a
    vulnerability per se but noted as Informational).

    Not-vulnerable condition: File present with a valid contact
    address and encryption public key.

    Record: Informational finding only.

## Payload Library

Categories (summaries inline; full secret-detection regexes in
`references/signatures.md`):

- **AWS key patterns**: `AKIA[0-9A-Z]{16}`, `ASIA[0-9A-Z]{16}`,
  secret key heuristics
- **GCP keys**: `AIza[0-9A-Za-z_-]{35}`
- **GitHub tokens**: `ghp_[0-9A-Za-z]{36}`, `gho_`, `ghu_`, `ghs_`
- **Slack tokens**: `xox[baprs]-[0-9A-Za-z-]+`
- **Private keys**: `BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY`
- **Generic high-entropy strings**: base64-like > 32 chars in
  config-looking files
- **`.git/` probe paths**: `HEAD`, `config`, `index`, `logs/HEAD`,
  `refs/heads/*`
- **`.bash_history` probe paths**: common deploy-user locations

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-798 (hard-coded creds) for repo/MR leaks. CWE-522
  (insufficiently protected creds) for pipeline-var leaks. CWE-918
  (SSRF) for webhook vectors. CWE-538 (info exposure) for `.git/`
  / `.bash_history` leaks.
- **OWASP**: WSTG-CONF-02 for pipeline configs; API7:2019 for
  security misconfiguration; API9:2023 (Improper Inventory
  Management) for runner/webhook inventory gaps.
- **CVSS vectors**: exposed production admin token —
  `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`. Exposed `.git/` on
  production — `...C:H/I:N/A:N`. Privileged runner with Docker-
  socket mount — `...PR:L/C:H/I:H/A:H`.
- **Evidence**: repo path + commit SHA + line number for code
  leaks; policy/pipeline YAML excerpt for config leaks; runner ID
  + config for runner findings; HTTP request/response for `.git/`
  and `.bash_history` leaks.
- **Remediation framing**: platform/DevOps engineer. Include:
  - GitLab CI/CD vault migration snippets (GitLab Secret File,
    External Secrets Operator, HashiCorp Vault integration)
  - Runner hardening (`privileged = false`, no socket mount,
    group-scoped tokens)
  - `.git/` directory exclusion in nginx/Apache configs
  - Secret rotation scripts per key type

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every secret-exposure finding has the commit SHA or
      issue/MR URL, never a raw secret value in plaintext
- [ ] Every secret finding is paired with a rotation
      recommendation and a vault-migration snippet
- [ ] No pipeline was triggered during the audit (grep Skills Run
      Log for any `glab ci run|retry` — should be zero)
- [ ] No MR was created, merged, or commented on
- [ ] Runner-posture findings include the runner ID and the
      specific misconfig (privileged vs socket mount vs shared)
- [ ] Webhook-SSRF testing only ran if scope explicitly approved
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Sandbox / test credentials**: Keys found in commits belong to
  decommissioned dev accounts with no prod access. Still file as
  a finding because (a) the commit history itself is a leak and
  (b) the rotation should verify the key is actually dead, but
  severity is Low/Informational rather than Critical.

- **Already-rotated secrets**: The secret existed in a past commit
  and has since been rotated. The commit itself is still a
  finding — anyone who cloned between the commit and the rotation
  has the old value. Severity depends on how long the exposure
  window was.

- **Honeytokens**: Some orgs commit fake credentials with
  alerting to detect attackers. Validating (via an `aws-iam-hunter`
  call) may trigger an internal incident. Coordinate with the
  security team before validating any obviously-public keys.

- **Long-lived `variables:` entries that aren't actually secrets**:
  GitLab CI variables named `API_URL` or `DEPLOY_HOST` look
  sensitive but are often just endpoint references, not secrets.
  Filter by entropy and context.

- **Shared runners pattern misread**: Some orgs explicitly use
  shared runners for OSS projects — not a vulnerability when the
  project itself is public and has no sensitive secrets. Confirm
  the project classification before filing.

## References

- `references/signatures.md` — full secret-detection regex catalog
- `references/remediation.md` — pipeline hardening + secret-vault
  migration snippets

External:
- GitLab CI/CD security best practices:
  https://docs.gitlab.com/ee/ci/pipelines/pipeline_security.html
- GitLab Runner security:
  https://docs.gitlab.com/runner/security/
- CWE-798: https://cwe.mitre.org/data/definitions/798.html
- CWE-522: https://cwe.mitre.org/data/definitions/522.html

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia de Segurança e Auditoria em Pipelines CI_CD GitLab.md`

Grounded in:
- Bug Bounty Bootcamp, Ch 5 (Recon) + Ch 21 (Exposed Directories)
- Hacking APIs, Ch 6 (Passive Recon)
- OWASP WSTG v4.2 (Section 4.1.3)
- OWASP API Security Top 10 (API7:2019, API9:2023)
- zseano's methodology (Webhook SSRF)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
