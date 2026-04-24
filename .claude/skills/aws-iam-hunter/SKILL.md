---
name: aws-iam-hunter
description: "Audits AWS IAM posture for over-privileged roles, exposed long-lived access keys, SSRF-reachable IMDS credential leaks, dangling DNS records pointing at decommissioned AWS resources, and API responses leaking internal ARNs. Use when the target runs on AWS and the assessment scope includes cloud-account review; when SSRF has been confirmed by another skill; or when the orchestrator's recon surfaces AWS-style resource names. Produces findings with CWE-732 / CWE-918 mapping, IAM-policy JSON evidence, and least-privilege remediation. Defensive testing only, against assets listed in .claude/security-scope.yaml — READ-ONLY AWS API calls only."
model: opus
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
  source_methodology: "Guia de Auditoria e Segurança em Misconfigurações AWS IAM.md"
  service_affecting: false
  composed_from: []
---

# AWS IAM Hunter

## Goal

Audit the target AWS account's IAM posture for configurations that would
let an attacker convert a foothold (SSRF, leaked key, compromised role)
into broader account access. This skill implements WSTG-CONF-11 and maps
findings to CWE-732 (Incorrect Permission Assignment for Critical
Resource), CWE-918 (SSRF) for metadata variants, and CWE-798 (Use of
Hard-Coded Credentials) for leaked keys. The goal is to hand the platform
team a concrete list of risky policies, exposed credentials, and
over-privileged roles, with precise least-privilege JSON snippets and
remediation owners.

## When to Use

- The target application runs on AWS (EC2, ECS, Lambda, Fargate, EKS) —
  confirmed by the scope file's `cloud: aws` entry or IMDS reachability
  from a prior SSRF finding.
- Another skill (`ssrf-hunter`, `ssrf-cloud-metadata-hunter`) confirmed
  SSRF reaches 169.254.169.254 — use this skill to enumerate what the
  recovered role can do.
- The organization stores data in S3 — audit bucket ACLs and policies.
- Public code repositories (GitHub, GitLab) for the org need a secrets
  sweep for AWS keys (overlaps with `secrets-in-code-hunter` — defer
  code-wide secret hunting there; this skill only VALIDATES discovered
  keys).
- The orchestrator selects this skill after `attack-surface-mapper`
  identifies AWS DNS records or `*.amazonaws.com` URLs in scope.

## When NOT to Use

- For exploiting the confirmed findings (e.g., chaining an IAM
  misconfig into cross-account pivot) — this is a defensive audit;
  confirmed issues go to `harden` for remediation.
- For discovering SSRF vulnerabilities themselves — use `ssrf-hunter`
  first, then this skill to enumerate impact.
- For code-repository secret hunting at scale — use
  `secrets-in-code-hunter`; this skill validates keys that have already
  surfaced.
- For S3 bucket misconfigurations discovered via enumeration without
  access — use `s3-misconfig-hunter` for bucket-policy deep-dives;
  this skill is account-wide IAM posture.
- For Azure / GCP — scope must include `cloud: aws`. Different clouds
  have different skills (none written yet — file a gap).
- Any asset not listed in `.claude/security-scope.yaml`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or
   doesn't parse, halt and report.
2. Confirm the AWS account ID (or the asset name pattern like
   `*.aws-account-12345.s3.amazonaws.com`) appears in the `assets`
   list AND its `testing_level` is at least `passive`. IAM read-only
   audits count as passive from the target's perspective — no
   workloads are touched.
3. Confirm the current principal (`aws sts get-caller-identity`) is a
   credentials-vault-provided audit role, NOT a developer's personal
   credentials. Log the principal ARN in the audit log. Halt if
   unexpected principal.
4. If the scope file names specific AWS services as out-of-scope (e.g.,
   "no reading CloudTrail"), honor that. Only call verbs listed in this
   skill's `allowed-tools` AND permitted by the scope.
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with
   status `running`. Include the AWS account ID and principal ARN.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier (usually the AWS account ID or a
  named asset like `api.internal.example.com`)
- `{aws_profile}`: the named profile in `~/.aws/credentials` to use —
  must be the audit-read-only profile
- `{region}`: primary AWS region; secondary regions enumerated via
  `ec2 describe-regions`
- `{candidate_keys}`: optional — list of AWS access key IDs discovered
  via OSINT or code review, to validate (NOT to exploit)

## Methodology

### Phase 1: Identify Current Principal and Scope

1. **Fingerprint the caller principal**
   [Bug Bounty Bootcamp, Ch 13]

   Do: Run `aws sts get-caller-identity --profile {aws_profile}`.
   Confirm the ARN matches the expected audit role.

   Vulnerable condition: N/A (this is verification).

   Record: Principal ARN, account ID, user ID in
   `.claude/planning/{issue}/iam-audit-context.md`.

2. **Enumerate account-wide permissions of the audit principal**
   [WSTG v4.2, p. 984]

   Do: Run `aws iam list-attached-role-policies` and
   `aws iam list-role-policies` on the audit role. Record what the
   audit itself can see — if visibility is restricted, findings may
   undercount risk.

   Record: Attached and inline policies for the audit role.

### Phase 2: Audit IAM Users and Roles for Over-Privilege

3. **List all IAM users + access-key metadata** [WSTG v4.2, WSTG-CONF-11]

   Do: `aws iam list-users` → for each user, `aws iam list-access-keys`
   and `aws iam get-access-key-last-used`.

   Vulnerable response: Users with multiple active access keys; users
   with access keys older than 90 days; users with `PasswordLastUsed`
   and `AccessKey` both in use (interactive + programmatic on one
   identity).

   Not-vulnerable response: Each user has one active key rotated in
   under 90 days and roles are used for workload access.

   Record: Per-user key age and usage report.

4. **List all roles with `sts:AssumeRole` exposure**
   [Bug Bounty Bootcamp, Ch 13]

   Do: `aws iam list-roles` → for each role, inspect
   `AssumeRolePolicyDocument`. Flag roles whose trust policy allows:
   - `Principal: "*"` (anyone can assume)
   - `Principal: {AWS: "arn:aws:iam::<ACCOUNT>:root"}` without
     `Condition` (whole account can assume)
   - Cross-account trusts to accounts outside the org
   - `Condition: {StringEquals: {sts:ExternalId: "<value>"}}` —
     confirm the external ID is not a well-known value

   Record: Each risky trust as a potential FINDING-NNN.

5. **Identify policies granting broad privilege** [OWASP API9:2019]

   Do: For each role and user, retrieve attached and inline policies.
   Parse JSON with `jq`. Flag any Statement that combines `Effect:
   Allow` with `Resource: "*"` or `Action: "*"` or
   `Action: "iam:PassRole"` without a `Resource` scoping.

   Use `aws iam simulate-principal-policy` to confirm whether the
   principal would actually be granted the risky action in context.

   Vulnerable condition: Admin-equivalent policies attached to
   service-role principals; `iam:PassRole` with wildcard `Resource`;
   `ec2:RunInstances` + `iam:PassRole` combo (privilege escalation
   vector).

   Record: FINDING-NNN per overbroad policy, include the policy JSON.

### Phase 3: Validate Discovered Credentials (READ-ONLY)

6. **Probe candidate access keys** [Bug Bounty Bootcamp, Ch 5, p. 67]

   Do: For each key in `{candidate_keys}` (discovered via OSINT):
   - Configure the AWS CLI with the key under a temp profile name
     (e.g., `audit-candidate-key-1`)
   - Run only `aws sts get-caller-identity` to determine the
     principal the key belongs to
   - Run `aws iam get-user` (for IAM users) to get user-level perms —
     do NOT attempt destructive or exploration commands

   Vulnerable response: Key returns a valid principal with active
   permissions — finding: leaked credentials with impact.

   Not-vulnerable response: `InvalidClientTokenId` or
   `ExpiredToken` — key is already deactivated.

   Record: Per-key principal, permissions summary (from simulate),
   recommended rotation action.

### Phase 4: SSRF-Adjacent IMDS Exposure

7. **Enumerate IMDS configuration on EC2 instances**
   [Bug Bounty Bootcamp, Ch 13, p. 226]

   Do: `aws ec2 describe-instances` → inspect each instance's
   `MetadataOptions.HttpTokens`.

   Vulnerable condition: `HttpTokens: optional` (IMDSv1 allowed) — an
   SSRF from a workload can reach IMDS without session-token gymnastics.

   Not-vulnerable condition: `HttpTokens: required` (IMDSv2
   enforced).

   Record: List of instances still accepting IMDSv1 with the role
   attached to each. Each IMDSv1 instance paired with a SSRF-reachable
   workload is a chained finding.

### Phase 5: S3 Bucket Posture

8. **List buckets and public-access blocks** [WSTG v4.2, p. 984]

   Do: `aws s3api list-buckets` → for each bucket,
   `aws s3api get-public-access-block` and `get-bucket-acl`.

   Vulnerable condition: `PublicAccessBlock` is missing or any of the
   four flags (`BlockPublicAcls`, `BlockPublicPolicy`,
   `IgnorePublicAcls`, `RestrictPublicBuckets`) is `false`. Also flag
   ACLs granting `AllUsers` or `AuthenticatedUsers` read/write.

   Record: Per-bucket posture, cross-reference with
   `s3-misconfig-hunter` for deeper bucket-policy analysis.

### Phase 6: Dangling DNS and Asset Drift

9. **Identify dangling DNS records** [WSTG v4.2, p. 982]

   Do: Read the scope file's DNS/CNAME inventory (if present) or
   enumerate via Route53 (`aws route53 list-resource-record-sets`).
   Check each CNAME pointing at AWS services (`*.s3.amazonaws.com`,
   `*.elasticbeanstalk.com`, `*.cloudfront.net`) for liveness.

   Vulnerable condition: CNAME resolves to an AWS resource that no
   longer exists (bucket deleted, ELB torn down) — subdomain takeover
   risk.

   Record: Each dangling CNAME as a FINDING-NNN; cross-reference
   `subdomain-takeover-hunter` for exploit-side confirmation.

## Payload Library

No attack payloads for this skill — it's read-only audit commands. The
key probes are:

- **IMDS path (via SSRF, NOT from this skill)**:
  `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- **IMDSv2 handshake check**:
  `curl -X PUT ".../latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60"`
- **STS validation**:
  `aws sts get-caller-identity --profile {candidate-key-profile}`
- **S3 bucket listing**: `aws s3api list-objects-v2 --bucket {name}`
  (read-only; does NOT use `aws s3 cp` or `aws s3 sync`)

Full command matrix in `references/tooling.md`.

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per the
schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-732 (Incorrect Permission Assignment) for IAM
  misconfig. CWE-918 (SSRF) for IMDSv1 + reachable workload. CWE-798
  for leaked credentials.
- **OWASP**: WSTG-CONF-11. For APIs, map to API9:2023 (Improper
  Inventory Management) for dangling assets, API5:2023 (BFLA) if
  admin IAM roles back end-user authorization.
- **CVSS vectors**: broad admin policy on service role —
  `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`. Leaked active key —
  `...PR:N/C:H/I:H/A:H`. IMDSv1 without confirmed SSRF — lower
  (`...PR:N/C:L/I:L/A:L`) — severity rises when paired with a
  reachable SSRF.
- **Evidence**: the policy JSON, the affected principal ARN, the
  `aws iam simulate-principal-policy` output confirming impact, and
  the least-privilege JSON remediation.
- **Remediation framing**: platform/infra engineer. Include
  least-privilege JSON snippets in `references/remediation.md` for
  common patterns (EC2 instance role, Lambda execution role,
  CI/CD deploy role).

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every finding includes the policy/config JSON and a principal
      ARN
- [ ] Every over-privilege finding includes an
      `aws iam simulate-principal-policy` result
- [ ] No write AWS verb was executed (grep the Skills Run Log for
      `create-|update-|delete-|put-|attach-|detach-|run-|start-|stop-`)
- [ ] No discovered key was used for exploration beyond
      `get-caller-identity` / `get-user`
- [ ] Each leaked-key finding is paired with a rotation recommendation
      owned by platform/infra
- [ ] CloudTrail lookups (if any) stayed within read-only `lookup-events`
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Deactivated but still-reported keys**: OSINT-discovered keys may
  already be rotated — STS returns `InvalidClientTokenId`. Not a
  vulnerability — but note in the audit that the key was found and
  that its deactivation is verified.

- **Sandbox account credentials**: Keys grant access to an isolated
  sandbox account with no production data. Lower-severity finding but
  still worth reporting — sandboxes should also enforce key rotation.

- **IMDSv2 reachable but never abused**: `HttpTokens: optional` on an
  instance that has no reachable SSRF is latent risk, not an active
  vuln. Severity Medium; raise to High if paired with a reachable
  SSRF confirmed by another skill.

- **Audit role sees less than actual**: If the audit principal has
  `iam:ListUsers` but not `iam:GetUserPolicy`, policy findings
  undercount. Note the visibility gap in the audit context file so
  downstream reviewers know how much of the account was actually
  inspected.

- **Cross-account trust with `ExternalId`**: A trust policy with
  `Principal: "*"` but gated by `Condition: StringEquals:
  sts:ExternalId` is only as safe as the ExternalId's secrecy.
  Flag if the ExternalId is short, guessable, or committed to a
  shared doc.

## References

- `references/tooling.md` — AWS CLI command matrix for each
  audit phase (safe command catalog)
- `references/remediation.md` — least-privilege IAM policy JSON
  snippets for common patterns

External:
- WSTG-CONF-11: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/11-Test_Cloud_Storage
- CWE-732: https://cwe.mitre.org/data/definitions/732.html
- AWS IAM Best Practices:
  https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- AWS IMDSv2 Transition Guide:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia de Auditoria e Segurança em Misconfigurações AWS IAM.md`

Grounded in:
- Bug Bounty Bootcamp, Ch 5 (Recon), Ch 13 (SSRF and cloud)
- The Web Application Hacker's Handbook, Ch 10 (Attacking Back-End Components)
- OWASP WSTG v4.2 (WSTG-CONF-11, WSTG-ATHN-02)
- OWASP API Security Top 10 (API3:2019, API7:2019, API9:2019)
- zseano's methodology (Cloud recon)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
