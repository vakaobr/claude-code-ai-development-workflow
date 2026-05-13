---
model: sonnet
---

## Cloud: AWS Cost Estimate

Generate a cost baseline + projection for an AWS-deployed change using [aws-doctor](https://github.com/elC0mpa/aws-doctor).

**Default mode (issue-tied):** `$ARGUMENTS` is a kebab-case issue name. Output lands in `.claude/planning/$ARGUMENTS/05c_COST_BASELINE.md` and links from `00_STATUS.md`.

**Standalone mode:** if `$ARGUMENTS` is empty OR equals `--adhoc`, the report is written to `.claude/reports/aws-cost-{YYYY-MM-DD-HHMM}.md` and is NOT linked to any planning issue.

### Pre-Conditions

- `aws-doctor` is installed (run `/cloud/aws-doctor-setup` if not)
- `AWS_PROFILE` is set (or default profile is configured)
- In issue mode: `.claude/planning/$ARGUMENTS/01_DISCOVERY.md` exists and detected stack includes AWS

### Instructions

#### 1. Resolve Mode

```bash
if [[ -z "$ARGUMENTS" || "$ARGUMENTS" == "--adhoc" ]]; then
  MODE=adhoc
  OUT=".claude/reports/aws-cost-$(date +%Y-%m-%d-%H%M).md"
  mkdir -p .claude/reports
else
  MODE=issue
  ISSUE="$ARGUMENTS"
  test -d ".claude/planning/$ISSUE" || { echo "No planning dir for $ISSUE"; exit 1; }
  OUT=".claude/planning/$ISSUE/05c_COST_BASELINE.md"
fi
```

In issue mode, read `01_DISCOVERY.md` and `03_ARCHITECTURE.md` (if present) to identify which AWS services the change touches. Use that to focus the waste scan and to interpret the cost report.

#### 2. Capture Current Account Baseline

```bash
aws-doctor report cost --path /tmp/aws-doctor-cost.pdf
aws-doctor report cost --output json > /tmp/aws-doctor-cost.json
```

The JSON is what we'll parse and embed. The PDF is for stakeholders — attach it to the issue/PR.

#### 3. Capture Trend Context

```bash
aws-doctor report trend --output json > /tmp/aws-doctor-trend.json
```

Use the 6-month trend to flag whether the *current* cost shape is already on an upward slope vs. flat — affects how aggressively we should size the new change.

#### 4. Project Incremental Cost (Issue Mode Only)

For each new AWS resource introduced by the change (from `03_ARCHITECTURE.md` if present, else from `01_DISCOVERY.md`):

- Map resource type → service → unit cost via `aws pricing get-products` (region-aware).
- Multiply by expected scale (RPS, storage GB, hours of runtime, etc. — read from `03_PROJECT_SPEC.md` non-functional requirements).
- Sum, then express as **monthly $ delta**.

If the architecture doc lacks scale numbers, ask the user once and write the assumption into the report.

#### 5. Produce the Report

Write to `$OUT`:

```markdown
# AWS Cost Baseline — {issue-name or "ad-hoc"}

**Generated:** {timestamp}
**Profile:** {AWS_PROFILE}
**Account ID:** {from sts get-caller-identity}
**Region focus:** {detected region(s)}

## Current Account Spend (last 30d)

| Service | $ Spend | % of Total |
|---------|--------:|-----------:|
| ... | ... | ... |

> Source: `aws-doctor report cost`. PDF: `/tmp/aws-doctor-cost.pdf`.

## 6-Month Trend

{ASCII trend chart from `aws-doctor report trend`, or describe direction: ↑↓→ per service}

**Flag:** {"Trending up >15% MoM in {service}" | "Stable" | etc.}

## Projected Delta for This Change   ← issue mode only

| New Resource | Service | Unit Cost | Quantity | $ / month |
|--------------|---------|----------:|---------:|----------:|
| ... | ... | ... | ... | ... |
| **Total delta** | | | | **${N}/mo** |

**Assumptions:**
- {scale assumption 1}
- {scale assumption 2}

## Recommendations

- {if delta > threshold, suggest cost-control measures: reserved instances, savings plans, right-sizing}
- {if trend is upward, suggest running /cloud/aws-waste-scan before deploying}
- {if cost-of-ownership is non-trivial, suggest adding it to 09_DEPLOY_PLAN.md "Cost" section}

## Links

- PDF report: `/tmp/aws-doctor-cost.pdf`
- Raw cost JSON: `/tmp/aws-doctor-cost.json`
- Raw trend JSON: `/tmp/aws-doctor-trend.json`
```

#### 6. Post-Actions

**Issue mode only:**

1. Append a row to `.claude/planning/$ISSUE/00_STATUS.md` under `## Artifacts`:
   ```
   - 05c_COST_BASELINE.md — ${N}/mo projected delta
   ```
2. If `09_DEPLOY_PLAN.md` already exists, append a `## Cost Impact` section linking to `05c_COST_BASELINE.md` and surfacing the **monthly delta**.

**Always:**

- Print the report path and the headline number (current spend, projected delta) to the user.

### Quality Gates

- `aws-doctor report cost` ran without `AccessDenied`
- Current-spend table has ≥1 row per top-5 services
- Issue mode: projected delta has explicit assumptions and is grounded in a real architecture doc
- Issue mode: `00_STATUS.md` references the new artifact
- PDF and JSON paths are valid (files exist)
