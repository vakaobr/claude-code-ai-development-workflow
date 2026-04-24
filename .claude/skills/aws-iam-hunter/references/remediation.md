# remediation — aws-iam-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia de Auditoria e Segurança em Misconfigurações AWS IAM.md` (Section 8: REMEDIATION)

---

## 1. Enforce Least Privilege

The default state for every IAM role / user should be "no access". Add
specific actions on specific resources, not `"Action": "*"` or
`"Resource": "*"`.

### Terraform — explicit, narrow policy

```hcl
data "aws_iam_policy_document" "app_read_specific_bucket" {
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]
    resources = [
      aws_s3_bucket.app_docs.arn,
      "${aws_s3_bucket.app_docs.arn}/*",
    ]
  }
}

resource "aws_iam_policy" "app_read_specific_bucket" {
  name   = "app-read-docs"
  policy = data.aws_iam_policy_document.app_read_specific_bucket.json
}
```

### Avoid AWS-managed policies like `AdministratorAccess`

Use `PowerUserAccess` / `ReadOnlyAccess` only for human break-glass
accounts, never for service roles.

### Use `aws-accessanalyzer` to generate policies from CloudTrail

```bash
# Access Analyzer: "IAM Access Analyzer policy generation"
# Generate a least-privilege policy based on 90 days of actual API calls:
aws accessanalyzer start-policy-generation \
  --policy-generation-details principalArn=arn:aws:iam::123456789012:role/AppRole
# Wait for completion, then:
aws accessanalyzer get-generated-policy --job-id <JOB_ID>
```

---

## 2. Eliminate Long-Lived Access Keys

### For human users

Replace IAM user + access key with SSO + short-lived STS tokens.

```hcl
# AWS IAM Identity Center (formerly SSO)
resource "aws_ssoadmin_permission_set" "dev_readonly" {
  name             = "DevReadOnly"
  instance_arn     = data.aws_ssoadmin_instances.this.arns[0]
  session_duration = "PT4H"
}

resource "aws_ssoadmin_managed_policy_attachment" "dev_readonly" {
  instance_arn        = data.aws_ssoadmin_instances.this.arns[0]
  managed_policy_arn  = "arn:aws:iam::aws:policy/ReadOnlyAccess"
  permission_set_arn  = aws_ssoadmin_permission_set.dev_readonly.arn
}
```

Human uses `aws sso login --profile dev` → gets a 4-hour STS credential.
No long-lived key exists.

### For CI/CD

Replace IAM user + access key with OIDC role-assumption.

```hcl
# GitHub Actions → AWS
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "github_deploy" {
  name = "github-deploy-prod"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:myorg/myrepo:ref:refs/heads/main"
        }
      }
    }]
  })
}
```

In the pipeline, use `aws-actions/configure-aws-credentials@v4` with
`role-to-assume`.

### For EC2 / ECS / EKS workloads

Use instance profiles (EC2), task roles (ECS), or IRSA (EKS) — never
hardcoded keys.

---

## 3. Enforce IMDSv2 Only

Prevents an SSRF from stealing the instance's role credentials.

```hcl
resource "aws_instance" "app" {
  # ...
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}
```

Also set account-wide:

```bash
aws ec2 modify-instance-metadata-defaults \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

(See `ssrf-cloud-metadata-hunter/references/remediation.md` for full
IMDS hardening.)

---

## 4. Manage Secrets via AWS Secrets Manager / SSM Parameter Store

Never hardcode credentials in env vars, config files, or source code.

### Secrets Manager

```hcl
resource "aws_secretsmanager_secret" "db_password" {
  name                    = "prod/app/db-password"
  recovery_window_in_days = 7
  rotation_lambda_arn     = aws_lambda_function.secret_rotator.arn
  rotation_rules {
    automatically_after_days = 30
  }
}
```

### Application consumption (Python)

```python
import boto3, json
client = boto3.client("secretsmanager")
resp = client.get_secret_value(SecretId="prod/app/db-password")
creds = json.loads(resp["SecretString"])
```

---

## 5. Monitor and Alert

### Enable CloudTrail org-wide

```hcl
resource "aws_cloudtrail" "org" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_organization_trail         = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
}
```

### Alert on high-risk IAM events

```bash
# EventBridge rule: fire on IAM CreateAccessKey, AttachUserPolicy,
# PutUserPolicy, CreateLoginProfile, PassRole to Administrator...
aws events put-rule \
  --name iam-sensitive-events \
  --event-pattern file://iam_pattern.json
```

### Enable GuardDuty

Detects `InstanceCredentialExfiltration.OutsideAWS` and similar
findings automatically.

```bash
aws guardduty create-detector --enable
aws guardduty create-detector --enable --data-sources S3Logs={Enable=true},Kubernetes={AuditLogs={Enable=true}}
```

---

## 6. Remove Dangling DNS Records

When an S3 bucket or CloudFront distribution is decommissioned, delete
the Route 53 CNAME pointing at it, or the subdomain becomes claimable
by anyone who creates a same-named bucket in another account.

```bash
# Audit dangling S3 CNAMEs:
aws route53 list-hosted-zones | jq -r '.HostedZones[].Id' | while read zone; do
  aws route53 list-resource-record-sets --hosted-zone-id "$zone" \
    --query "ResourceRecordSets[?Type=='CNAME' && contains(ResourceRecords[0].Value, 's3')]"
done
```

For each CNAME pointing at an S3 bucket, verify the bucket still exists
and is owned by you.

---

## 7. S3 Bucket Hardening (quick note; see `s3-misconfig-hunter/remediation.md` for full)

- Enable `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`,
  `RestrictPublicBuckets` on every account (Account-level Block Public
  Access).
- Enforce bucket encryption (`aws:kms` for sensitive data).
- Enable versioning + MFA-delete for audit-trail buckets.

---

## 8. Dependency and Config Scans in CI

- Run `gitleaks` / `trufflehog` in every pipeline to catch committed
  AWS keys.
- Run `checkov` / `tfsec` / `terraform validate` on Terraform changes to
  catch over-permissive `iam_policy_document` blocks.

```yaml
# .github/workflows/security.yml (excerpt)
- uses: bridgecrewio/checkov-action@master
  with:
    directory: terraform/
    check: CKV_AWS_*
```

---

## Framework / Service Quick-Reference

| Control                              | AWS primitive                                                 |
|--------------------------------------|---------------------------------------------------------------|
| Human access                         | IAM Identity Center (SSO) — NOT IAM users                     |
| CI/CD access                         | OIDC role-assumption (GitHub / GitLab / Bitbucket OIDC)       |
| EC2 / ECS / EKS workload access      | Instance profile / ECS task role / IRSA                       |
| Metadata hardening                   | `http_tokens=required` on all instances                       |
| Secret storage                       | Secrets Manager or SSM Parameter Store (SecureString)         |
| Audit trail                          | Org-wide CloudTrail + log-file validation                     |
| Anomaly detection                    | GuardDuty + EventBridge rules on IAM events                   |
| Continuous policy review             | IAM Access Analyzer + `aws-accessanalyzer` reports            |

---

## 9. Incident Response Playbook (when credentials are confirmed leaked)

1. Rotate / deactivate the access key immediately.
2. Scan CloudTrail for the last 30 days using the exposed
   `AccessKeyId` as a filter — identify every API call made.
3. Rotate any secondary credentials the attacker may have fetched.
4. Check for newly created IAM users, access keys, roles.
5. Check for `ConsoleLogin` events from unusual IPs.
6. Check S3 bucket policies and Resource-based IAM policies for new
   cross-account `Principal`s.
7. Audit Lambda functions for unfamiliar code updates.
8. If a role was exploited, revoke all sessions:
   `aws iam put-role-policy --role-name X --policy-name DenyAll --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"2026-04-23T00:00:00Z"}}}]}'`
