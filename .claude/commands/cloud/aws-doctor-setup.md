---
model: sonnet
---

## Cloud: AWS Doctor — Install & Verify

One-time setup for [aws-doctor](https://github.com/elC0mpa/aws-doctor), the Go CLI used by `/cloud/aws-cost-estimate`, `/cloud/aws-waste-scan`, and `/cloud/aws-trend`.

### Instructions

#### 1. Detect Existing Install

```bash
command -v aws-doctor && aws-doctor --version
```

If present, skip to Step 3.

#### 2. Install

Pick the appropriate installer for the platform. Confirm with the user before running.

| Platform | Command |
|----------|---------|
| macOS (Homebrew) | `brew install elC0mpa/homebrew-tap/aws-doctor` |
| macOS / Linux | `curl -fsSL https://raw.githubusercontent.com/elC0mpa/aws-doctor/main/install.sh \| bash` |
| Windows (PowerShell) | `iwr -useb https://raw.githubusercontent.com/elC0mpa/aws-doctor/main/install.ps1 \| iex` |
| Any (Go ≥ 1.21) | `go install github.com/elC0mpa/aws-doctor@latest` |

Verify after install:

```bash
aws-doctor --version
```

#### 3. Verify AWS Credentials

aws-doctor reads the standard AWS SDK chain: env vars, shared config/credentials, IAM roles. Confirm the active profile:

```bash
aws sts get-caller-identity --profile $AWS_PROFILE
```

If the profile uses MFA, aws-doctor will prompt for the token at runtime. No extra config needed.

#### 4. Verify Required IAM Permissions

The tool needs **read-only** access to the services it scans plus `pricing:GetProducts`. Minimum policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ce:GetCostAndUsage",
        "pricing:GetProducts",
        "ec2:Describe*",
        "rds:Describe*",
        "elasticloadbalancing:Describe*",
        "lambda:List*", "lambda:Get*",
        "sagemaker:List*", "sagemaker:Describe*",
        "ecr:Describe*", "ecr:List*",
        "secretsmanager:List*", "secretsmanager:Describe*",
        "s3:List*", "s3:GetBucketLocation",
        "cloudwatch:GetMetricStatistics", "cloudwatch:ListMetrics"
      ],
      "Resource": "*"
    }
  ]
}
```

Run a smoke check (cheapest call):

```bash
aws-doctor waste ec2 --output json | head -50
```

If it returns without `AccessDenied`, setup is complete.

#### 5. Update Permissions Allowlist

If `aws-doctor` is not yet in `.claude/settings.json` under `permissions.allow`, add:

```json
"Bash(aws-doctor *)"
```

so subsequent runs don't prompt.

### Quality Gates

- `aws-doctor --version` returns a version string
- `aws sts get-caller-identity` succeeds for the intended profile
- Smoke `waste ec2 --output json` returns without permission errors
- `Bash(aws-doctor *)` is in `.claude/settings.json` allowlist

### Next Steps

- `/cloud/aws-cost-estimate {issue-name}` — baseline cost for a planning issue
- `/cloud/aws-waste-scan` — ad-hoc account-wide waste sweep
- `/cloud/aws-trend` — 6-month trend report
