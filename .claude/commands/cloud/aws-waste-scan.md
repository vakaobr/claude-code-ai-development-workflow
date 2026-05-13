---
model: sonnet
---

## Cloud: AWS Waste Scan

Identify idle / under-utilized AWS resources using [aws-doctor](https://github.com/elC0mpa/aws-doctor) `waste`.

**Default mode (issue-tied):** first positional arg matches an existing planning dir → results land in `.claude/planning/{issue}/05d_AWS_WASTE.md`.

**Standalone mode:** no issue arg, or first arg is `--adhoc` → results land in `.claude/reports/aws-waste-{YYYY-MM-DD-HHMM}.md`.

**Service filter:** any remaining args are passed as service filters to aws-doctor. Supported: `ec2`, `s3`, `cloudwatch`, `rds`, `vpc`, `lambda`, `sagemaker`, `elb`, `ecr`, `secrets-manager`.

### Pre-Conditions

- `aws-doctor` is installed (run `/cloud/aws-doctor-setup` if not)
- Read-only IAM permissions on the services being scanned

### Usage Examples

```bash
/cloud/aws-waste-scan                              # standalone, all services
/cloud/aws-waste-scan ec2 rds                      # standalone, only ec2+rds
/cloud/aws-waste-scan migrate-ecs-app              # issue-tied, all services
/cloud/aws-waste-scan migrate-ecs-app ec2 lambda   # issue-tied, ec2+lambda only
```

### Instructions

#### 1. Parse Arguments

```bash
ARGS=($ARGUMENTS)
FIRST="${ARGS[0]}"
KNOWN_SERVICES="ec2 s3 cloudwatch rds vpc lambda sagemaker elb ecr secrets-manager"

if [[ -z "$FIRST" || "$FIRST" == "--adhoc" ]]; then
  MODE=adhoc
  SERVICES=("${ARGS[@]:1}")
  OUT=".claude/reports/aws-waste-$(date +%Y-%m-%d-%H%M).md"
  mkdir -p .claude/reports
elif [[ -d ".claude/planning/$FIRST" ]]; then
  MODE=issue
  ISSUE="$FIRST"
  SERVICES=("${ARGS[@]:1}")
  OUT=".claude/planning/$ISSUE/05d_AWS_WASTE.md"
elif [[ " $KNOWN_SERVICES " == *" $FIRST "* ]]; then
  MODE=adhoc
  SERVICES=("${ARGS[@]}")
  OUT=".claude/reports/aws-waste-$(date +%Y-%m-%d-%H%M).md"
  mkdir -p .claude/reports
else
  echo "Unknown arg: $FIRST (not a planning dir, not --adhoc, not a known service)"
  exit 1
fi
```

#### 2. Run the Scan

```bash
aws-doctor waste "${SERVICES[@]}" --output json > /tmp/aws-doctor-waste.json
aws-doctor waste "${SERVICES[@]}" --output table > /tmp/aws-doctor-waste.txt
```

If MFA is required, aws-doctor prompts inline. Pass through to the user.

#### 3. Rank & Categorize Findings

Parse `/tmp/aws-doctor-waste.json` and bucket findings into:

| Priority | Criteria |
|----------|----------|
| **P0 — Quick win** | Idle ≥30d, monthly cost ≥ $50, safe to delete (no DNS pointers, no recent access) |
| **P1 — Confirm & remove** | Idle ≥30d, monthly cost $10–$50, needs owner confirmation |
| **P2 — Right-size** | Active but over-provisioned (CPU < 10%, mem < 30%, Lambda memory > 2x p99 usage) |
| **P3 — Watchlist** | Recently-created idle resources (<30d), or low-cost (<$10/mo) |

For each finding, capture:
- Resource ARN
- Resource type
- Estimated monthly cost
- Age / last-used signal (if available)
- Suggested action (delete | downsize | confirm-with-owner | monitor)

#### 4. Write the Report

```markdown
# AWS Waste Scan — {issue-name or "ad-hoc"}

**Generated:** {timestamp}
**Profile:** {AWS_PROFILE} ({account-id})
**Services scanned:** {list, or "all"}
**Estimated monthly waste:** **${total}/mo**

## Quick Wins (P0)

| Resource | Service | $/mo | Idle since | Action |
|----------|---------|-----:|------------|--------|
| ... | ... | ... | ... | delete |

## Confirm & Remove (P1)

...

## Right-Size (P2)

...

## Watchlist (P3)

...

## Methodology

- Source: `aws-doctor waste {services}`
- Region(s): {detected from output}
- Idle thresholds: aws-doctor defaults (typically CPU < 5% for 30d)
- Region-aware pricing via `pricing:GetProducts`

## Raw Output

- JSON: `/tmp/aws-doctor-waste.json`
- Table: `/tmp/aws-doctor-waste.txt`
```

#### 5. Post-Actions

**Issue mode:**

- Append to `.claude/planning/$ISSUE/00_STATUS.md` under `## Artifacts`:
  ```
  - 05d_AWS_WASTE.md — ${total}/mo waste identified ({P0count} quick wins)
  ```
- If P0 count ≥ 1, surface in the user-facing summary as **"Found {N} quick wins worth ${X}/mo — review 05d_AWS_WASTE.md before deploying"**.

**Standalone mode:**

- Print report path + headline number to the user.
- Suggest opening Jira tickets for P0 items (do NOT create automatically — user-triggered).

### Quality Gates

- aws-doctor exited 0; no `AccessDenied` errors
- Every P0 finding has an ARN and a suggested action
- Total monthly waste in the headline matches the sum of per-finding costs
- In issue mode, the artifact is linked from `00_STATUS.md`
