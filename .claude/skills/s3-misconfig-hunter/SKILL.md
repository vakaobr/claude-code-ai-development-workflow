---
name: s3-misconfig-hunter
description: "Audits Amazon S3 buckets for public-list / public-read / public-write ACLs, permissive bucket policies, and block-public-access gaps. Uses AWS CLI read operations (list-objects-v2, get-bucket-acl, get-bucket-policy, get-public-access-block) — NO uploads, no deletes. Distinct from aws-iam-hunter (account-wide IAM) — this skill deep-dives per-bucket posture. Use when the target uses S3 for storage; when `web-recon-passive` surfaces `s3.amazonaws.com` URLs; or when `aws-iam-hunter` flags buckets for deeper review. Produces findings with CWE-732 / CWE-200 mapping and Block-Public-Access + bucket-policy remediation. Defensive testing only — READ-ONLY AWS CLI."
model: sonnet
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  Bash(aws:iam get-*), Bash(aws:iam list-*),
  Bash(aws:iam simulate-principal-policy*),
  Bash(aws:s3api get-*), Bash(aws:s3api list-*),
  Bash(aws:s3api head-*),
  Bash(aws:ec2 describe-*),
  Bash(aws:rds describe-*),
  Bash(aws:lambda get-*), Bash(aws:lambda list-*),
  Bash(aws:cloudtrail lookup-events),
  Bash(aws:configservice describe-*),
  Bash(aws:sts get-caller-identity),
  Bash(jq:*), Bash(yq:*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: cloud
  authorization_required: true
  tier: T3
  source_methodology: "Segurança e Auditoria de Buckets Amazon S3.md"
  service_affecting: false
  composed_from: []
---

# S3 Misconfig Hunter

## Goal

Deep-dive per-bucket audit of Amazon S3 bucket configurations —
Access Control Lists (ACLs), bucket policies, public-access
blocks, encryption, versioning, logging, and MFA-delete settings.
Complements `aws-iam-hunter`'s account-wide IAM review with
bucket-specific posture. Implements WSTG-CONF-11 and maps
findings to CWE-732 (Incorrect Permission Assignment for
Critical Resource) + CWE-200 (Information Exposure). The goal is
to hand the platform team a concrete list of misconfigured
buckets with Block-Public-Access + restrictive-policy
remediation. READ-ONLY audit — no `cp`, `sync`, or `rm`.

## When to Use

- The target uses S3 for storage (confirmed by scope
  `asset_type: aws_s3` OR `s3.amazonaws.com` URLs in recon).
- `aws-iam-hunter` flagged specific buckets for deeper review.
- `web-recon-passive` found public bucket references in
  JavaScript bundles or API responses.
- The orchestrator requests a per-bucket posture sweep
  (e.g., compliance audit preparation).

## When NOT to Use

- For account-wide IAM posture — use `aws-iam-hunter`.
- For bucket-takeover scenarios (dangling CNAME to deleted
  bucket) — use `subdomain-takeover-hunter`.
- For data-exfiltration confirmation — this skill only checks
  CONFIGURATION; verifying that an attacker could download
  specific objects is a gated operator-level action.
- For non-AWS cloud storage (GCS, Azure Blob) — file a gap;
  this skill is AWS-specific.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not at least `passive`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist
   or doesn't parse, halt and report.
2. Confirm the target (AWS account or specific bucket patterns
   like `*.aws-account-12345.s3.amazonaws.com`) appears in the
   `assets` list AND `testing_level` is at least `passive`.
3. Confirm `aws sts get-caller-identity` reports the audit-role
   principal, not a developer's personal credentials. Log the
   ARN.
4. Use ONLY read-only S3 verbs: `list-buckets`, `list-objects-v2`,
   `get-bucket-acl`, `get-bucket-policy`, `get-public-access-block`,
   `get-bucket-encryption`, `get-bucket-versioning`,
   `get-bucket-logging`, `get-bucket-website`. NEVER use
   `cp`, `sync`, `rm`, `put-*`, or any write verb (tool profile
   blocks these but this skill must not attempt).
5. For buckets where listing is denied but individual-object
   access might be possible, DO NOT attempt to guess object
   names — that's data-exfiltration, not configuration audit.
6. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
   with status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the AWS account ID or asset pattern
- `{aws_profile}`: named AWS profile with audit credentials
- `{bucket_list}`: optional — specific buckets to scan (if
  empty, enumerates via `list-buckets`)

## Methodology

### Phase 1: Bucket Enumeration

1. **List all accessible buckets** [WSTG v4.2, WSTG-CONF-11]

   Do: `aws s3api list-buckets --profile {aws_profile} --query 'Buckets[].Name' --output json | jq -r '.[]'`

   Record: Per-bucket name list in
   `.claude/planning/{issue}/s3-bucket-inventory.md`.

2. **Discover OSINT-referenced buckets not in inventory**
   [Bug Bounty Bootcamp, Ch 5, p. 60]

   Do: Cross-reference `PASSIVE_RECON.md` and
   `ATTACK_SURFACE.md` for any `*.s3.amazonaws.com` URLs or
   bucket-naming patterns. Filter against the inventory to find
   buckets that:
   - Are referenced in the target's JS bundles / API responses
     but NOT in the audit-role's visible inventory (cross-
     account bucket, or bucket in a different region)

   For each such bucket, run `aws s3api head-bucket --bucket
   {name}` to confirm existence. A 200 response = exists,
   accessible. 403 = exists but blocked. 404 = doesn't exist.

   Record: OSINT-vs-inventory delta matrix.

### Phase 2: Per-Bucket ACL Audit

3. **Get bucket ACL** [WSTG v4.2, 4.2.11]

   Do: For each bucket:
   ```bash
   aws s3api get-bucket-acl --bucket {name} --profile {aws_profile} \
     | jq '.Grants'
   ```

   Flag Grantees of:
   - `URI: http://acs.amazonaws.com/groups/global/AllUsers`
     — public (anyone on the internet)
   - `URI: http://acs.amazonaws.com/groups/global/AuthenticatedUsers`
     — "any AWS user" (essentially public — any AWS account
     can assume)

   Plus Permission ≥ `READ`.

   Vulnerable condition: Any AllUsers or AuthenticatedUsers
   grant with READ / WRITE / READ_ACP / WRITE_ACP / FULL_CONTROL.

   Record: Per-bucket ACL matrix.

### Phase 3: Public-Access Block

4. **Check Block-Public-Access settings**
   [AWS Best Practices]

   Do:
   ```bash
   aws s3api get-public-access-block --bucket {name} --profile {aws_profile} \
     | jq '.PublicAccessBlockConfiguration'
   ```

   Expected (secure) response:
   ```json
   {
     "BlockPublicAcls": true,
     "IgnorePublicAcls": true,
     "BlockPublicPolicy": true,
     "RestrictPublicBuckets": true
   }
   ```

   Vulnerable condition: ANY flag is `false` OR the call returns
   `NoSuchPublicAccessBlockConfiguration` (no PAB set).

   Record: Per-bucket PAB status.

### Phase 4: Bucket Policy Audit

5. **Parse bucket policy JSON** [OWASP API Security]

   Do:
   ```bash
   aws s3api get-bucket-policy --bucket {name} --profile {aws_profile} \
     | jq -r '.Policy' \
     | jq '.'
   ```

   Flag Statements with:
   - `Effect: Allow` AND
   - `Principal: "*"` OR `Principal: {AWS: "*"}`
   - NO `Condition` block
   - Actions including `s3:GetObject` / `s3:PutObject` /
     `s3:ListBucket` / `s3:DeleteObject`

   Also flag:
   - `Action: "s3:*"` with wildcard resource
   - Cross-account Principal grants to accounts outside the
     expected org

   Vulnerable condition: Unconditional-public read/write policy.

   Record: Per-bucket policy excerpt + risk rating.

### Phase 5: List + Public-Read Verification

6. **Check list-ability**
   [WSTG v4.2, 4.2.11, p. 920]

   Do:
   ```bash
   aws s3api list-objects-v2 --bucket {name} --max-items 5 --profile {aws_profile}
   ```

   (Limit to 5 items to avoid downloading an entire enumeration
   — `--max-items 5` caps the response.)

   Vulnerable signal: Bucket lists contents despite audit
   principal having no explicit list grant (means public-list
   is enabled).

   Also try unauthenticated list (no profile):
   ```bash
   aws s3api list-objects-v2 --bucket {name} --max-items 5 --no-sign-request
   ```

   Vulnerable signal: Anonymous list succeeds.

   Record: Per-bucket listability status.

### Phase 6: Server-Side Configuration Review

7. **Server-side encryption (SSE) status**
   [Compliance requirement]

   Do:
   ```bash
   aws s3api get-bucket-encryption --bucket {name} --profile {aws_profile}
   ```

   Vulnerable condition: `NoSuchEncryptionConfiguration` (bucket
   has no default encryption — data at rest is unencrypted).

   Not-vulnerable: SSE-S3 / SSE-KMS / SSE-C default set.

   Record: Finding Medium unless the bucket holds PII / financial
   data (then High).

8. **Versioning status**
   [Compliance + recovery]

   Do:
   ```bash
   aws s3api get-bucket-versioning --bucket {name} --profile {aws_profile}
   ```

   Vulnerable condition: `Status: Disabled` on buckets holding
   critical data (no protection against accidental /
   malicious overwrites).

   Record: Medium severity.

9. **Logging status** [Compliance]

   Do:
   ```bash
   aws s3api get-bucket-logging --bucket {name} --profile {aws_profile}
   ```

   Vulnerable condition: No `LoggingEnabled` config — any
   access to the bucket is unlogged (no forensic trail after
   incident).

   Record: Medium severity.

### Phase 7: Website Configuration

10. **Static-website hosting check**
    [Information exposure]

    Do:
    ```bash
    aws s3api get-bucket-website --bucket {name} --profile {aws_profile}
    ```

    Vulnerable condition: Website hosting is enabled AND
    public-read is enabled — means the bucket is intentionally
    serving public content. Verify that ALL bucket contents are
    intended as public (not mixed with sensitive internal
    files).

    Record: Mark buckets "intended-public" vs "accidentally-
    public".

## Payload Library

No payloads — AWS CLI read calls. Key probes:

- **list-buckets**: account-wide enumeration
- **head-bucket**: existence confirmation
- **get-bucket-acl**: ACL audit
- **get-public-access-block**: PAB check
- **get-bucket-policy**: policy JSON
- **list-objects-v2** (capped): list-ability check
- **get-bucket-encryption**: SSE status
- **get-bucket-versioning**: versioning status
- **get-bucket-logging**: access-logging status
- **get-bucket-website**: static-hosting config

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-732 (incorrect permission assignment). CWE-200
  for any exposure. CWE-16 (configuration) for missing
  defaults.
- **OWASP**: WSTG-CONF-11. For APIs, API7:2023 (Security
  Misconfiguration). A05:2021.
- **CVSS vectors**: public read of a bucket with PII —
  `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`. Public write (arbitrary
  upload → potential malware hosting / data poisoning) —
  `...I:H/A:L`. Public list with internally-sensitive file
  names — `...C:L/I:N/A:N` (info disclosure about structure).
  Missing encryption — compliance-driven severity.
- **Evidence**: the ACL / policy JSON excerpt, the
  PAB status, the list-objects-v2 result (if list succeeded),
  and a classification of the bucket's contents based on
  name/purpose.
- **Remediation framing**: platform / infra engineer. Include:
  - Block Public Access at account level
    (`aws s3control put-public-access-block --account-id
    {ACCOUNT_ID} --public-access-block-configuration ...`)
  - Per-bucket PAB — same flags all `true`
  - Restrictive bucket policy — deny `s3:*` for
    `Principal: "*"`
  - Enable SSE-KMS with customer-managed key for sensitive
    data
  - Enable versioning + MFA-delete for critical buckets
  - Enable access logging to a dedicated audit bucket
  - For websites: use a dedicated bucket with explicit
    public-intent, keep other buckets private by default

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every bucket in the inventory has ACL + PAB + policy +
      encryption + versioning + logging status recorded
- [ ] No `cp`, `sync`, `rm`, or write verb was executed (grep
      the Skills Run Log)
- [ ] Anonymous probes (`--no-sign-request`) used ONLY for
      public-list confirmation, not for data download
- [ ] Per-bucket finding distinguishes "intended-public"
      (websites) from "accidentally-public"
- [ ] Cross-reference with `aws-iam-hunter`'s principal list —
      any discovered role has an IAM review?
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Access Denied on listing, but individual objects readable**:
  Some buckets restrict `ListBucket` but allow `GetObject` for
  any known object name. This is worse than public-list because
  it's harder to detect. If the bucket's purpose suggests it
  holds semi-structured data, note the risk in the finding.

- **Honeypot bucket**: Intentionally exposed bucket with
  monitoring. Attackers who probe get logged. Coordinate with
  security team before extensive testing of "too easy"
  findings.

- **Public assets by design**: Marketing sites, documentation,
  public logos. Don't file public-read findings for these
  unless sensitive contents are MIXED in.

- **Cross-account / cross-org policy grant**: A bucket policy
  grants access to an AWS account ID that looks like a partner
  or vendor. Verify the account belongs to the expected third
  party. An unexpected cross-account grant is a finding even
  if it's a legitimate partner — wrong grants happen.

- **PAB present but policy overrides**: PAB at the account level
  was enabled, but a specific bucket has an explicit override.
  PAB respects bucket-level settings for certain operations.
  Check both.

- **Stale IAM role attached**: A bucket's access policy grants
  a role that no longer exists. Not a current vulnerability
  but indicates drift — note for cleanup.

## References

External:
- WSTG-CONF-11: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/11-Test_Cloud_Storage
- AWS S3 Security Best Practices:
  https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html
- AWS Block Public Access:
  https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
- CWE-732: https://cwe.mitre.org/data/definitions/732.html

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Segurança e Auditoria de Buckets Amazon S3.md`

Grounded in:
- Bug Bounty Bootcamp, Ch 5 (AWS Recon)
- OWASP WSTG v4.2 (WSTG-CONF-11)
- OWASP API Security Top 10 (API7:2019)
- AWS Security best practices documentation

Conversion date: 2026-04-24
Conversion prompt version: 1.0
