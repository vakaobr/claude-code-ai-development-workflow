---
model: sonnet
---

## Cloud: cloud-cost-cli — Install & Verify

One-time setup for [cloud-cost-cli](https://github.com/vuhp/cloud-cost-cli), the multi-cloud (AWS / Azure / GCP) cost analyzer used by `/cloud/cost-scan` and `/cloud/aws-cost-compare`.

Use this in addition to `/cloud/aws-doctor-setup` when you want:
- Azure / GCP coverage (aws-doctor is AWS-only)
- A second opinion on AWS findings via `/cloud/aws-cost-compare`

### Instructions

#### 1. Detect Existing Install

```bash
command -v cloud-cost-cli && cloud-cost-cli --version
```

If present, skip to Step 3.

#### 2. Install

```bash
node --version          # must be ≥ 20
npm install -g cloud-cost-cli
cloud-cost-cli --version
```

Confirm with the user before running `npm install -g` if global installs are gated in this environment.

#### 3. Verify Per-Provider Credentials

Run only the checks for clouds you actually use. Each is read-only.

**AWS** — needs `ReadOnlyAccess` (or equivalent IAM):
```bash
aws sts get-caller-identity --profile $AWS_PROFILE
```

**Azure** — needs `Reader` role on the subscription:
```bash
az account show
# If creating a fresh service principal:
# az ad sp create-for-rbac --name "cloud-cost-cli" --role Reader \
#   --scopes /subscriptions/$AZURE_SUBSCRIPTION_ID
```

**GCP** — needs `Compute Viewer` + `Storage Viewer` + `Cloud SQL Viewer`:
```bash
gcloud auth list
gcloud config get-value project
```

If any cloud's CLI is not installed, note it in the report but don't block — the user may only need one provider.

#### 4. Smoke Tests

Run the cheapest possible scan per available provider:

```bash
# AWS — small region, JSON output, top-5 findings
cloud-cost-cli scan --provider aws --region us-east-1 --output json --top 5 > /tmp/cc-aws-smoke.json

# Azure
cloud-cost-cli scan --provider azure --location eastus --output json --top 5 > /tmp/cc-azure-smoke.json

# GCP
cloud-cost-cli scan --provider gcp --region us-central1 --output json --top 5 > /tmp/cc-gcp-smoke.json
```

Verify each file is valid JSON and contains no `AccessDenied`-style errors.

#### 5. Initialize Config (Optional)

cloud-cost-cli supports a local config for default provider / region / output:

```bash
cloud-cost-cli config init
cloud-cost-cli config show
```

Recommend committing **nothing** from the config — it may capture account IDs. The config lives in the user's home dir by default.

#### 6. Update Permissions Allowlist

If not already present in `.claude/settings.json` under `permissions.allow`:

```json
"Bash(cloud-cost-cli *)",
"Bash(az account show*)",
"Bash(gcloud auth list*)",
"Bash(gcloud config get-value*)"
```

### Quality Gates

- `cloud-cost-cli --version` returns a version string
- At least one provider passed credential verification
- Each available provider's smoke scan returned valid JSON with no auth errors
- `Bash(cloud-cost-cli *)` is in the settings allowlist

### Next Steps

- `/cloud/cost-scan {issue} --provider {aws|azure|gcp}` — issue-tied multi-cloud scan
- `/cloud/aws-cost-compare {issue}` — run both aws-doctor + cloud-cost-cli, diff the results
