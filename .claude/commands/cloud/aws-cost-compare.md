---
model: sonnet
---

## Cloud: AWS Cost — Compare aws-doctor vs cloud-cost-cli

Run **both** [aws-doctor](https://github.com/elC0mpa/aws-doctor) and [cloud-cost-cli](https://github.com/vuhp/cloud-cost-cli) against the same AWS account, then diff the findings. The high-signal output is the **consensus list** (both tools agree → high confidence) and the **conflicting list** (one says idle, other says active → needs human review).

**Default mode (issue-tied):** `$ARGUMENTS` is a planning issue name → output lands in `.claude/planning/{issue}/05g_AWS_COMPARE.md`.

**Standalone mode:** `$ARGUMENTS` is empty or `--adhoc` → output lands in `.claude/reports/aws-compare-{YYYY-MM-DD-HHMM}.md`.

### Pre-Conditions

- Both tools installed: run `/cloud/aws-doctor-setup` and `/cloud/cost-cli-setup` first
- AWS credentials configured (`aws sts get-caller-identity` succeeds)

### Instructions

#### 1. Resolve Mode

```bash
if [[ -z "$ARGUMENTS" || "$ARGUMENTS" == "--adhoc" ]]; then
  MODE=adhoc
  OUT=".claude/reports/aws-compare-$(date +%Y-%m-%d-%H%M).md"
  mkdir -p .claude/reports
else
  MODE=issue
  ISSUE="$ARGUMENTS"
  test -d ".claude/planning/$ISSUE" || { echo "No planning dir for $ISSUE"; exit 1; }
  OUT=".claude/planning/$ISSUE/05g_AWS_COMPARE.md"
fi
```

#### 2. Run Both Tools

```bash
aws-doctor waste --output json > /tmp/awsdoc-waste.json
cloud-cost-cli scan --provider aws --output json > /tmp/cc-aws.json
```

Run in sequence (not parallel) — both may prompt for MFA and parallel prompts will mangle the terminal.

If either tool fails, halt and report which one. Don't fall back to a single-tool comparison — that defeats the purpose.

#### 3. Normalize Findings

Each tool reports findings with different field names. Map both to a common schema:

```
{
  resource_id: ARN or resource name,
  resource_type: ec2-instance | rds | lambda | ebs-volume | elb | ...,
  monthly_cost_usd: number,
  reason: "idle" | "oversized" | "unattached" | "orphaned" | ...,
  source: "aws-doctor" | "cloud-cost-cli",
  confidence: HIGH | MEDIUM | LOW (cloud-cost-cli only — aws-doctor implicitly HIGH)
}
```

Use the resource ID/ARN as the join key. When IDs differ in format (aws-doctor may use ARN, cloud-cost-cli may use short name) normalize to the ARN form.

#### 4. Bucket the Findings

| Bucket | Definition | Confidence Signal |
|--------|------------|-------------------|
| **Consensus** | Same resource ID in both tools | **Very high** — act first |
| **aws-doctor only** | In aws-doctor, not in cloud-cost-cli | aws-doctor's region-aware pricing is stronger; treat as HIGH |
| **cloud-cost-cli only** | In cloud-cost-cli, not in aws-doctor | cloud-cost-cli has 18 AWS analyzers (broader); check confidence label |
| **Conflicting** | Same resource ID, different `reason` (e.g., one says idle, other says oversized) | Needs human review |

#### 5. Write the Report

```markdown
# AWS Cost — Tool Comparison — {issue-name or "ad-hoc"}

**Generated:** {timestamp}
**Profile:** {AWS_PROFILE} ({account-id})
**Tools:** aws-doctor v{X}, cloud-cost-cli v{Y}

## Summary

| Bucket | Count | $/mo |
|--------|------:|-----:|
| Consensus (both tools) | N | $X |
| aws-doctor only | N | $X |
| cloud-cost-cli only | N | $X |
| Conflicting | N | $X |
| **Total unique waste** | **N** | **$X** |

**Recommendation:** start with Consensus findings — both tools flagged these independently.

## Consensus Findings

| Resource | Type | $/mo | Reason | Action |
|----------|------|-----:|--------|--------|
| ... | ... | ... | idle ≥30d | delete |

## aws-doctor Only

| Resource | Type | $/mo | Reason | Why cloud-cost-cli might have missed |
|----------|------|-----:|--------|--------------------------------------|
| ... | ... | ... | ... | (e.g., region not scanned, analyzer absent) |

## cloud-cost-cli Only

| Resource | Type | $/mo | Reason | Confidence | Why aws-doctor might have missed |
|----------|------|-----:|--------|------------|----------------------------------|
| ... | ... | ... | ... | HIGH | (e.g., new analyzer type, different threshold) |

## Conflicting Findings

| Resource | aws-doctor says | cloud-cost-cli says | $/mo | Recommended check |
|----------|-----------------|---------------------|-----:|-------------------|
| ... | idle | oversized-active | $X | Pull CloudWatch metrics manually |

## Methodology

- Run order: aws-doctor first, cloud-cost-cli second
- Join key: ARN (normalized when one tool reports short names)
- Cost figures: each tool's own region-aware estimate — for consensus findings, the higher of the two is reported (conservative)
- Conflict definition: same resource ID, different `reason` classifications

## Raw Output

- aws-doctor JSON: `/tmp/awsdoc-waste.json`
- cloud-cost-cli JSON: `/tmp/cc-aws.json`
```

#### 6. Post-Actions

**Issue mode:** append to `00_STATUS.md` under `## Artifacts`:
```
- 05g_AWS_COMPARE.md — N consensus, M conflicting (${total}/mo)
```

**Always:**

- Print headline to the user: consensus count + $/mo + conflicting count.
- Suggest opening tickets only for the consensus list (highest confidence). Conflicting findings should be triaged manually.

### Quality Gates

- Both tools ran successfully — no fallback to a single-tool report
- Join key is consistent (ARN form) across both inputs
- Conflicting bucket lists *both* tools' classifications, not just one
- Cost figures are explicit per finding (no "approximately" hand-waving)
- Recommendation explicitly prioritizes consensus findings
