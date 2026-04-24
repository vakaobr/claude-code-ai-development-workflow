# tooling — aws-iam-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia de Auditoria e Segurança em Misconfigurações AWS IAM.md` (Sections 4, 5: TEST METHODOLOGY / PAYLOADS)

All commands here fit the `cloud-readonly` tool profile: only
`describe-*`, `get-*`, `list-*`, `simulate-*` verbs. No `create-*`,
`update-*`, `delete-*`, `put-*`, `attach-*`, `detach-*`.

---

## Phase 1 — Identity & Attribution (who am I?)

```bash
# What principal am I using?
aws sts get-caller-identity

# Useful fields:
#   Account     — which AWS account
#   Arn         — which user / role
#   UserId      — principal ID
```

If the result is a role ARN (`arn:aws:sts::123456:assumed-role/Foo/i-0abc`),
enumerate the role's attached policies next. If it's an IAM user ARN
(`arn:aws:iam::123456:user/bob`), enumerate the user's policies and
groups.

---

## Phase 2 — Read-Only Enumeration

### IAM users, groups, roles

```bash
aws iam list-users
aws iam list-groups
aws iam list-roles
aws iam list-policies --scope Local        # customer-managed only
```

### A specific user

```bash
aws iam get-user --user-name alice
aws iam list-attached-user-policies --user-name alice
aws iam list-user-policies --user-name alice             # inline policies
aws iam list-groups-for-user --user-name alice
aws iam list-access-keys --user-name alice               # key status, last-used date
```

### A specific role

```bash
aws iam get-role --role-name AppRole
aws iam list-attached-role-policies --role-name AppRole
aws iam list-role-policies --role-name AppRole           # inline policies
aws iam get-role-policy --role-name AppRole \
    --policy-name InlinePolicyName                       # fetch inline doc
aws iam list-instance-profiles-for-role --role-name AppRole
```

### Policy contents

```bash
aws iam get-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam get-policy-version \
    --policy-arn arn:aws:iam::aws:policy/PowerUserAccess \
    --version-id v1
```

### Account password policy + MFA

```bash
aws iam get-account-password-policy
aws iam get-account-summary                              # MFA devices count, etc.
aws iam list-virtual-mfa-devices
```

### EC2 instance-profile review

```bash
aws ec2 describe-instances \
    --query 'Reservations[].Instances[].[InstanceId,IamInstanceProfile.Arn,MetadataOptions.HttpTokens]' \
    --output table
```

`HttpTokens` = `optional` means IMDSv1 is still enabled — flag.

### Access key age

```bash
aws iam generate-credential-report
aws iam get-credential-report \
    --query 'Content' --output text | base64 -d | \
    awk -F',' 'NR==1 || $10 != "false"'    # users with access_key_1_active=true
```

Keys older than 90 days should be rotated.

### Cross-account trust review

```bash
# Which external accounts can assume my roles?
for role in $(aws iam list-roles --query 'Roles[].RoleName' --output text); do
  aws iam get-role --role-name "$role" \
    --query 'Role.AssumeRolePolicyDocument' --output json | \
    jq --arg role "$role" '{role:$role, principals:.Statement[].Principal}'
done
```

Any `"Principal": {"AWS": "*"}` or a principal in an account outside
your org is a red flag.

---

## Phase 3 — Policy Simulation (what CAN this principal do?)

Use `iam simulate-principal-policy` to ask "if this principal requested
action X, would it be allowed?" This is a read-only simulation — it does
NOT perform the action.

```bash
# Single action
aws iam simulate-principal-policy \
    --policy-source-arn arn:aws:iam::123456:role/AppRole \
    --action-names s3:GetObject \
    --resource-arns arn:aws:s3:::sensitive-bucket/*

# Sweep of high-risk actions
aws iam simulate-principal-policy \
    --policy-source-arn arn:aws:iam::123456:role/AppRole \
    --action-names \
        iam:CreateUser \
        iam:AttachUserPolicy \
        iam:PutUserPolicy \
        iam:PassRole \
        s3:DeleteBucket \
        ec2:TerminateInstances \
        lambda:UpdateFunctionCode \
        kms:Decrypt \
    --output table
```

Entries where `EvalDecision == allowed` are potential privilege-escalation
paths.

### Using IAM Access Analyzer

```bash
# Enable (if not already)
aws accessanalyzer create-analyzer --analyzer-name audit --type ACCOUNT

# List findings
aws accessanalyzer list-findings \
    --analyzer-arn $(aws accessanalyzer list-analyzers --query 'analyzers[0].arn' --output text) \
    --filter 'status={eq=ACTIVE}'
```

Findings include:
- Roles trusting external accounts
- S3 buckets and KMS keys shared with external principals
- Lambdas exposed publicly

---

## Phase 4 — CloudTrail Lookup (what has this principal DONE?)

### Direct `lookup-events` (covers 90 days)

```bash
# All events for a specific principal (e.g., stolen IAM user)
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=alice \
    --start-time 2026-04-01T00:00:00Z \
    --end-time 2026-04-23T00:00:00Z \
    --max-results 50

# All IAM-related events
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventSource,AttributeValue=iam.amazonaws.com \
    --start-time 2026-04-22T00:00:00Z \
    --output json | jq '.Events[].EventName' | sort | uniq -c | sort -rn

# Console logins
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
    --start-time 2026-04-22T00:00:00Z
```

### For anything older, query via Athena / S3

```sql
-- Athena on the CloudTrail bucket
SELECT eventTime, eventName, userIdentity.arn, sourceIPAddress, userAgent
FROM cloudtrail_logs
WHERE eventTime > '2026-04-01'
  AND userIdentity.arn = 'arn:aws:iam::123456:user/alice'
ORDER BY eventTime DESC
LIMIT 500;
```

---

## Phase 5 — S3 & Bucket Review (handoff to `s3-misconfig-hunter`)

Short list of commands most relevant during an IAM audit:

```bash
# Enumerate buckets and their public-access settings
aws s3api list-buckets --query 'Buckets[].Name' --output text | tr '\t' '\n' | \
while read b; do
  echo "=== $b ==="
  aws s3api get-public-access-block --bucket "$b" 2>/dev/null || echo "  no block config"
  aws s3api get-bucket-acl --bucket "$b" --query 'Grants[?Grantee.URI!=null].Grantee.URI' --output text
done
```

---

## Phase 6 — Credential Key Validation (stolen key?)

Set the suspect credentials in a throwaway shell:

```bash
unset AWS_PROFILE
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
unset AWS_SESSION_TOKEN

aws sts get-caller-identity                   # confirm they work
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query 'Arn' --output text | awk -F/ '{print $NF}')
```

Tools:
- **KeyHacks** (github.com/streaak/keyhacks) — quick check whether a
  key is valid AND which service it grants access to.
- **prowler** (github.com/prowler-cloud/prowler) — full read-only IAM /
  S3 / EC2 audit.
- **ScoutSuite** (github.com/nccgroup/ScoutSuite) — multi-cloud audit.
- **pacu** (github.com/RhinoSecurityLabs/pacu) — offensive AWS toolkit;
  most modules are DESTRUCTIVE, gated behind
  `destructive_testing: approved`.

---

## Safety Notes

- This skill is `cloud-readonly` — commands above are all get / list /
  describe / simulate. Do NOT run `aws iam create-*`, `aws iam put-*`,
  or `aws iam delete-*`.
- If a test demonstrates a privilege-escalation path via
  `simulate-principal-policy`, report it — do NOT attempt the actual
  escalation.
- Read-only commands are still logged by CloudTrail; avoid running the
  full sweep during sensitive windows (e.g., incident-response exercises)
  without notifying the tenant security team.
