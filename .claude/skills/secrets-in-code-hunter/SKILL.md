---
name: secrets-in-code-hunter
description: "Scans code repositories and git history for hardcoded credentials — AWS / GCP / Azure keys, API tokens, JWT signing secrets, database connection strings, SSH private keys, and generic high-entropy strings. Uses trufflehog / gitleaks plus custom regex over `git log`, `git show`, and file contents. Also audits exposed `.git/` directories and `.env` files on production. Use after `web-recon-passive` surfaces repo references; after `gitlab-cicd-hunter` identifies candidate repos; or when the orchestrator requests a org-wide secret sweep. Produces findings with CWE-798 / CWE-540 mapping, HASH-only evidence (never plaintext), and vault-migration + key-rotation remediation. Defensive testing only — READ-ONLY repo access."
model: sonnet
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  Bash(git:log*), Bash(git:show*), Bash(git:blame*), Bash(git:grep*),
  Bash(git:diff*), Bash(git:cat-file*), Bash(git:ls-files*),
  Bash(trufflehog:*), Bash(gitleaks:detect*), Bash(gitleaks:protect*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: cicd
  authorization_required: true
  tier: T3
  source_methodology: "Segredos em Código_ Detecção e Resposta a Vazamentos.md"
  service_affecting: false
  composed_from: []
---

# Secrets in Code Hunter

## Goal

Scan code repositories, git history, and exposed production
configuration for hardcoded credentials — AWS / GCP / Azure
keys, API tokens, JWT signing secrets, database connection
strings, SSH private keys, and generic high-entropy strings.
This skill complements `gitlab-cicd-hunter` (which focuses on
CI/CD-specific surface) with broader org-wide scanning via
trufflehog / gitleaks. Implements WSTG-INFO-05 and maps findings
to CWE-798 (Use of Hard-Coded Credentials) + CWE-540 (Inclusion
of Sensitive Information in Source Code). The goal is to hand
the platform / security team a concrete list of exposed secrets
with HASH-only storage (never plaintext) and vault-migration +
key-rotation remediation.

## When to Use

- `web-recon-passive` surfaced public repositories for the target
  org.
- `gitlab-cicd-hunter` or `excessive-data-exposure-hunter`
  identified secret-candidate strings that need deeper scanning.
- The orchestrator requests a comprehensive org-wide secret
  sweep.
- Post-incident — after a leak is suspected, confirm scope by
  scanning all commit history.

## When NOT to Use

- For GitLab-CI/CD-specific pipeline config review — use
  `gitlab-cicd-hunter` (which focuses on the pipeline layer).
- For validating DISCOVERED keys against live cloud services —
  use `aws-iam-hunter` (AWS validation) or equivalent. This
  skill finds keys; other skills enumerate impact.
- For secrets in API RESPONSES (not source code) — use
  `excessive-data-exposure-hunter`.
- For secrets in client-side JavaScript bundles served by the
  live app — `excessive-data-exposure-hunter` covers that;
  this skill focuses on the REPOSITORIES the bundles are built
  from.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not at least `passive`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist
   or doesn't parse, halt and report.
2. Confirm the target organization appears in the `assets` list
   AND its `testing_level` is at least `passive`. Secret-sweep
   is read-only — runs git commands against already-cloned
   copies, never modifies.
3. If the scope lists specific repos as in-scope vs
   out-of-scope, honor that. NEVER scan repos outside the
   declared scope, even if publicly reachable.
4. Discovered secrets MUST be stored HASHED (first/last 4 chars
   + sha256) in findings, NEVER plaintext. This is non-
   negotiable — a finding with plaintext secrets can leak in
   downstream reports.
5. If a discovered secret appears to be ACTIVELY USED (high
   entropy, looks unsullied, recent commit), IMMEDIATELY flag
   for rotation. Cross-reference `aws-iam-hunter` for
   AWS-specific validation but DO NOT validate from this skill.
6. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
   with status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset or organization identifier
- `{scope_context}`: optional — specific repos to focus on
- `{repo_list}`: list of authorized repos to scan (paths on
  disk if cloned, or GitHub/GitLab URLs for fetch)

## Methodology

### Phase 1: Repo Inventory

1. **Enumerate authorized repos**
   [Bug Bounty Bootcamp, Ch 5, p. 89]

   Do: From `web-recon-passive`'s public-repo findings OR a
   scope-provided `{repo_list}`, confirm each repo is
   in-scope. Clone each locally (read-only) to
   `.claude/planning/{issue}/repos/`.

   Record:
   `.claude/planning/{issue}/secrets-in-code-inventory.md` with
   repo paths + commit-count metadata.

### Phase 2: Full-History Scan with trufflehog

2. **Run trufflehog with high-entropy detection**
   [Hacking APIs, Ch 6]

   Do: For each repo:
   ```bash
   trufflehog git file://{repo_path} \
     --json \
     --only-verified > {repo_path}.trufflehog.json
   ```

   `--only-verified` drastically reduces false positives by
   only reporting secrets trufflehog could verify against the
   live service (AWS STS validation, GitHub token endpoint
   probes, etc.).

   Parse JSON output:
   ```bash
   jq -r '. | "\(.DetectorType) \(.SourceMetadata.Data.Git.commit) \(.SourceMetadata.Data.Git.file)"' \
     {repo_path}.trufflehog.json | sort -u
   ```

   Record: Per-hit (detector, commit SHA, file) in
   `secrets-in-code-hunter-hits.md`.

3. **Run gitleaks with full-history scan**
   [Bug Bounty Bootcamp, Ch 21]

   Do: Gitleaks uses pattern-based detection (regex families
   per provider) — catches patterns trufflehog misses. Run:
   ```bash
   gitleaks detect --source={repo_path} \
     --report-format=json \
     --report-path={repo_path}.gitleaks.json
   ```

   Record: Per-finding — rule ID (e.g., `aws-access-key`),
   commit, file, line, match.

### Phase 3: Custom Regex Grep (Coverage Supplement)

4. **High-signal pattern sweep**
   [Bug Bounty Bootcamp, Ch 5, p. 67]

   Do: Run targeted grep for patterns that generic tools may
   miss (company-specific patterns, JWT signing secrets with
   brand prefixes, internal URL schemes):
   ```bash
   git -C {repo_path} log --all --pretty=format:%H | while read commit; do
     git -C {repo_path} show $commit \
       | grep -E "(AKIA|ASIA|AIza|ghp_|gho_|ghu_|ghs_|ghr_|sk_live_|sk_test_|xox[baprs]-|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+|-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----|mongodb(\+srv)?://[^:]+:[^@]+@|postgres://[^:]+:[^@]+@|redis://[^:]+:[^@]+@|[Bb]earer\s+[A-Za-z0-9_\-\.=]+)" \
       | head -5
   done
   ```

   Record: Supplementary findings.

### Phase 4: Commit-History Deletion Recovery

5. **Audit "secret removal" commits**
   [Hacking APIs, Ch 6, p. 210]

   Do: `git log --all -p` over the full history. Look for diff
   blocks showing `-` lines that contain secret patterns
   (indicating a secret was DELETED but remains in history).

   ```bash
   git -C {repo_path} log --all -p \
     | grep -B 2 -A 2 "^-.*\(AKIA\|password\s*=\s*\"\|api_key\s*=\s*\"\|secret\s*=\s*\"\)" \
     | head -50
   ```

   Vulnerable signal: A commit removes `AKIA...` but the
   earlier commit that ADDED it is still in history. Anyone
   with a clone captured between the two commits has the
   secret.

   Record: Per-commit hit with the commit SHA of BOTH the
   addition and the removal.

### Phase 5: Exposed Git / Config Files on Production

6. **Probe production host for `/.git/` leakage**
   [WSTG v4.2, 4.2.4]

   Do: For each production host in scope (overlap with
   `gitlab-cicd-hunter` Phase 3), probe:
   ```
   /.git/HEAD
   /.git/config
   /.git/index
   /.git/logs/HEAD
   /.git/refs/heads/main
   ```

   If the server returns git content, the full repo can be
   reconstructed via tools like `git-dumper`.

   NOTE: This skill's `repo-readonly` profile doesn't include
   `curl` in its allowed-tools — this step delegates the live
   probing to `web-recon-active`, which has curl. If
   `ATTACK_SURFACE.md` already flagged `.git/` exposure, read
   that finding and chain it here.

   Record: Cross-referenced findings.

7. **Probe for `.env`, `web.config`, `.npmrc`, etc.**
   [WSTG v4.2, 4.2.4]

   Do: Same delegation pattern — `web-recon-active` probes
   live hosts for common config paths. This skill reads the
   results and cross-references with repo-captured secret
   findings.

### Phase 6: Hash and Rotate

8. **Hash storage + rotation flag**
   [This skill's invariant]

   Do: For every finding:
   - Store the secret as `{first4}...{last4}...{sha256}`
     (first 4 chars + last 4 + sha256 of the full value)
   - NEVER write the plaintext secret anywhere in the audit
   - Immediately note the finding with a ROTATION
     recommendation, marking the team that owns the
     credential

   For known-validatable secret types (AWS keys, GitHub tokens,
   Stripe keys), set a flag for `aws-iam-hunter` or
   equivalent to validate — but the validation happens in that
   OTHER skill, not this one.

   Record: Per-finding rotation directive + validation handoff.

## Payload Library

Full regex catalog in `references/signatures.md`. Categories:

- **Cloud keys**: AWS (AKIA / ASIA), GCP (AIza), Azure
  (connection strings)
- **Platform tokens**: GitHub (ghp_, gho_, ghu_, ghs_, ghr_),
  GitLab (glpat-), Slack (xox[baprs]-), Stripe (sk_live / sk_test),
  Twilio, SendGrid, Mailgun
- **JWT-like patterns**: `ey...eY...` (dot-separated base64)
- **Private keys**: `BEGIN (RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY`
- **DB connection strings**: `mongodb://` / `postgres://` /
  `mysql://` / `redis://` with embedded credentials
- **Bearer tokens**: `Authorization: Bearer ...` patterns
- **Generic high-entropy**: strings >32 chars with base64
  alphabet in config-like files

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-798 (hardcoded creds). CWE-540 (sensitive info in
  source code). CWE-200 for context (information exposure).
- **OWASP**: WSTG-INFO-05. For APIs, API7:2023 (Security
  Misconfiguration). A07:2021 (Identification and
  Authentication Failures) if the secret is an auth token.
- **CVSS vectors**: leaked AWS root key —
  `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`. Leaked service-
  account token — similar. Leaked test-env sandbox token —
  lower (`...C:L/I:L/A:N`).
- **Evidence**: the commit SHA + file path + line + the
  HASH-only secret reference. Include the detection tool that
  caught it (trufflehog / gitleaks / custom-regex) and whether
  verification is possible.
- **Remediation framing**: platform / DevOps engineer. Include:
  - Immediate rotation: CLI snippets per provider (AWS, GCP,
    GitHub, Stripe, etc.)
  - Vault migration: HashiCorp Vault, AWS Secrets Manager,
    Azure Key Vault, GCP Secret Manager
  - pre-commit hook enforcement: `gitleaks`, `talisman`,
    `detect-secrets`
  - git history rewrite (BFG Repo-Cleaner) WITH caveats —
    rewrite doesn't help if someone cloned before the rewrite,
    rotation is still primary
  - Access review: check whether the secret was USED between
    commit and discovery (cloud audit logs, API access logs)

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
- `.claude/planning/{issue}/aws-iam-targets.md` — AWS keys for
  `aws-iam-hunter` validation (HASH-only)
- `.claude/planning/{issue}/jwt-targets.md` — any JWT signing
  secrets discovered for `jwt-hunter` HS256-crack validation

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every finding cites the detection tool
      (trufflehog / gitleaks / custom-regex)
- [ ] Every finding stores the secret as HASH-only — grep the
      SECURITY_AUDIT for raw AKIA / BEGIN.*PRIVATE KEY / etc.
      patterns; should find zero outside the first4-last4
      format
- [ ] Verified secrets (trufflehog --only-verified hits) are
      flagged as immediate-rotate
- [ ] Already-rotated secrets (commits showing removal) are
      distinguished from still-active
- [ ] Handoff to `aws-iam-hunter` / `jwt-hunter` wrote keys to
      the right handoff files
- [ ] No scope-excluded repos were scanned
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **False positives from placeholder strings**: `api_key =
  "YOUR_KEY_HERE"` or `password = "PASSWORD"` aren't real
  credentials. trufflehog / gitleaks handle most; custom regex
  may need a denylist of obvious placeholders.

- **Honeytokens in public repos**: Orgs sometimes commit fake
  credentials with monitoring. Trufflehog's `--only-verified`
  mode may VALIDATE a honeytoken (it was designed to look real)
  — which triggers the defender's alert. Coordinate with the
  security team before extensive validation of public repo
  findings.

- **Rotated-but-in-history secrets**: The team rotated the key
  AFTER committing it. Finding the old key in history is still
  a finding — anyone cloning between commit-add and commit-
  rotate has it. Severity depends on how long the window was
  and whether audit logs show external access.

- **Sandbox / test account credentials**: `sk_test_...` Stripe
  keys, `AKIA...` keys in dedicated sandbox accounts — lower
  impact than prod but should still be rotated, and ideally
  never committed at all.

- **Commit author ≠ original author**: Someone merged a commit
  from a contributor whose identity is hard to contact for
  rotation. Team needs to rotate on behalf; this skill just
  reports.

- **Secrets in Git LFS objects**: Large-file-stored binaries
  may contain secrets (e.g., embedded credentials in exported
  databases). trufflehog / gitleaks may skip LFS content by
  default. If the repo uses LFS, note this as a coverage gap.

- **Non-git repositories (SVN, Mercurial)**: Tools are
  Git-centric. For non-Git repos, note as out-of-scope for
  this skill and recommend a dedicated SVN/Hg equivalent
  (rare, but exists).

## References

- `references/signatures.md` — full regex catalog + detector
  source attribution

External:
- trufflehog: https://github.com/trufflesecurity/trufflehog
- gitleaks: https://github.com/gitleaks/gitleaks
- CWE-798: https://cwe.mitre.org/data/definitions/798.html
- CWE-540: https://cwe.mitre.org/data/definitions/540.html
- OWASP WSTG v4.2 (WSTG-INFO-05, WSTG-CONF-04)

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Segredos em Código_ Detecção e Resposta a Vazamentos.md`

Grounded in:
- Hacking APIs, Ch 6 (OSINT) + Ch 21
- Bug Bounty Bootcamp, Ch 5 + Ch 21 + Ch 22
- OWASP WSTG v4.2 (WSTG-INFO-05, WSTG-CONF-04)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
