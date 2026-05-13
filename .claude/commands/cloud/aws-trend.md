---
model: sonnet
---

## Cloud: AWS Cost Trend (6-Month)

Generate a 6-month per-service cost trend using [aws-doctor](https://github.com/elC0mpa/aws-doctor) `report trend`. Useful for spotting silent cost creep before it shows up in finance reviews.

**Default mode (issue-tied):** first positional arg matches a planning dir → output lands in `.claude/planning/{issue}/05e_AWS_TREND.md`.

**Standalone mode:** no issue arg, or first arg is `--adhoc` → output lands in `.claude/reports/aws-trend-{YYYY-MM-DD-HHMM}.md`.

**Service filter:** remaining args are passed to aws-doctor (same list as `/cloud/aws-waste-scan`).

### Pre-Conditions

- `aws-doctor` is installed (run `/cloud/aws-doctor-setup` if not)
- IAM has `ce:GetCostAndUsage` and `pricing:GetProducts`

### Usage Examples

```bash
/cloud/aws-trend                              # standalone, all services, 6mo
/cloud/aws-trend ec2 rds                      # standalone, only ec2+rds
/cloud/aws-trend migrate-ecs-app              # issue-tied
/cloud/aws-trend migrate-ecs-app rds lambda   # issue-tied, filtered
```

### Instructions

#### 1. Parse Arguments

Same parsing logic as `/cloud/aws-waste-scan` — issue-tied if first arg is an existing planning dir, otherwise standalone.

#### 2. Run aws-doctor

```bash
aws-doctor report trend "${SERVICES[@]}" --output json > /tmp/aws-doctor-trend.json
aws-doctor report trend "${SERVICES[@]}" --output table > /tmp/aws-doctor-trend.txt
aws-doctor report trend "${SERVICES[@]}" --path /tmp/aws-doctor-trend.pdf
```

The ANSI chart is in the table output; the PDF is for stakeholder sharing.

#### 3. Analyze the Trend

Parse `/tmp/aws-doctor-trend.json` and classify each service:

| Pattern | Threshold |
|---------|-----------|
| **🔴 Runaway** | Month-over-month growth >15% for ≥3 of last 6 months |
| **🟡 Creeping** | MoM growth 5-15% sustained, OR a sudden ≥30% step-up in any single month |
| **🟢 Stable** | MoM swing within ±5% |
| **🔵 Decreasing** | MoM decline >5% sustained |

For runaway / creeping services, attempt to correlate with recent changes:
- Read `git log --since="6 months ago" --oneline` for deploys touching that service.
- Cross-reference with `.claude/planning/*/00_STATUS.md` files marked `WORKFLOW COMPLETE` in that window.
- Note correlations but do not assert causation — flag them as "candidates to investigate."

#### 4. Write the Report

```markdown
# AWS Cost Trend — {issue-name or "ad-hoc"}

**Generated:** {timestamp}
**Profile:** {AWS_PROFILE} ({account-id})
**Window:** Last 6 calendar months
**Services:** {list, or "all"}

## Summary

| Service | Pattern | 6mo Δ | Current $/mo |
|---------|---------|------:|-------------:|
| ec2 | 🔴 Runaway | +47% | $4,200 |
| rds | 🟢 Stable | +2% | $1,800 |
| ... | | | |

## Flagged Services

### {service} — 🔴 Runaway (+{N}%)

**Monthly progression:** $X → $Y → $Z → ...

**Correlated changes (candidates to investigate, not confirmed causes):**
- {commit / planning issue / date}
- {commit / planning issue / date}

**Suggested next step:**
- Run `/cloud/aws-waste-scan {service}` to check for accumulated idle resources
- Review the candidates above with the service owner

## ASCII Chart

```
{paste from /tmp/aws-doctor-trend.txt}
```

## Raw Output

- JSON: `/tmp/aws-doctor-trend.json`
- Table: `/tmp/aws-doctor-trend.txt`
- PDF: `/tmp/aws-doctor-trend.pdf`
```

#### 5. Post-Actions

**Issue mode:** append to `00_STATUS.md` under `## Artifacts`:
```
- 05e_AWS_TREND.md — {N} runaway, {M} creeping services
```

**Always:** print headline (number of runaway services, total $/mo of flagged services) to the user. Suggest `/cloud/aws-waste-scan {service}` for each runaway entry.

### Quality Gates

- aws-doctor exited 0
- Every service in the output has 6 monthly data points (or explicit "insufficient data" note)
- Runaway / creeping classifications use the documented thresholds, not vibes
- Correlations are labeled "candidates" — never asserted as causes
- In issue mode, artifact is linked from `00_STATUS.md`
