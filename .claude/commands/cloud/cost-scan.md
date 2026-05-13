---
model: sonnet
---

## Cloud: Multi-Cloud Cost Scan (cloud-cost-cli)

Run a cost-optimization scan against AWS, Azure, or GCP using [cloud-cost-cli](https://github.com/vuhp/cloud-cost-cli). Detects idle resources, over-sized instances, unattached volumes, and 11–18 other waste patterns per provider.

**Default mode (issue-tied):** first positional arg matches a planning dir → results land in `.claude/planning/{issue}/05f_CLOUD_COST.md`.

**Standalone mode:** no issue arg, or first arg is `--adhoc` → results land in `.claude/reports/cloud-cost-{provider}-{YYYY-MM-DD-HHMM}.md`.

### Pre-Conditions

- `cloud-cost-cli` is installed (run `/cloud/cost-cli-setup` if not)
- Credentials are configured for the target provider

### Usage

```bash
/cloud/cost-scan --provider aws                                  # standalone, AWS, default region
/cloud/cost-scan --provider azure --location eastus              # standalone, Azure
/cloud/cost-scan --provider gcp --all-regions                    # standalone, GCP all regions
/cloud/cost-scan migrate-ecs-app --provider aws                  # issue-tied
/cloud/cost-scan migrate-ecs-app --provider aws --detailed-metrics
```

### Instructions

#### 1. Parse Arguments

Tokens to extract from `$ARGUMENTS`:

| Token | Meaning |
|-------|---------|
| First positional matching `.claude/planning/{name}/` | issue-tied mode |
| First positional `--adhoc` or absent | standalone mode |
| `--provider {aws\|azure\|gcp}` | **required** |
| `--region X` / `--location X` / `--all-regions` | passed through |
| `--detailed-metrics` | passed through |
| `--top N` / `--min-savings $X` | passed through |

If `--provider` is missing, halt and ask the user.

#### 2. Resolve Output Path

```bash
if [[ "$MODE" == "issue" ]]; then
  OUT=".claude/planning/$ISSUE/05f_CLOUD_COST.md"
else
  OUT=".claude/reports/cloud-cost-$PROVIDER-$(date +%Y-%m-%d-%H%M).md"
  mkdir -p .claude/reports
fi
```

In issue mode, read `01_DISCOVERY.md` + `03_ARCHITECTURE.md` to identify which services the change touches — use that to interpret which findings are relevant to *this* change vs. account-wide background noise.

#### 3. Run the Scan

```bash
cloud-cost-cli scan \
  --provider "$PROVIDER" \
  $REGION_FLAG \
  $EXTRA_FLAGS \
  --output json > /tmp/cc-scan.json

cloud-cost-cli scan \
  --provider "$PROVIDER" \
  $REGION_FLAG \
  $EXTRA_FLAGS \
  --output html --top 50 > /tmp/cc-scan.html || true
```

`$REGION_FLAG` is `--region X` for AWS/GCP, `--location X` for Azure, or `--all-regions` if requested. The HTML output is best-effort and saved for stakeholder sharing.

#### 4. Categorize Findings

Parse `/tmp/cc-scan.json`. cloud-cost-cli emits **confidence levels** (HIGH / MEDIUM / LOW). Combine with monthly savings to bucket:

| Priority | Criteria |
|----------|----------|
| **P0 — Quick win** | confidence=HIGH AND monthly_savings ≥ $50 |
| **P1 — Confirm & remove** | confidence=HIGH AND $10–$50, OR confidence=MEDIUM AND ≥ $50 |
| **P2 — Right-size** | confidence=MEDIUM AND $10–$50, OR over-provisioning findings (any confidence) |
| **P3 — Watchlist** | confidence=LOW, OR savings < $10/mo |

For each finding capture: resource ID, analyzer that flagged it, monthly $ savings, confidence, suggested action.

#### 5. Write the Report

```markdown
# Multi-Cloud Cost Scan — {issue-name or "ad-hoc"}

**Generated:** {timestamp}
**Provider:** {aws|azure|gcp} ({account-id|subscription|project})
**Region(s):** {value}
**Tool:** cloud-cost-cli v{version}
**Estimated monthly savings identified:** **${total}/mo**

## Quick Wins (P0)

| Resource | Analyzer | $/mo | Confidence | Action |
|----------|----------|-----:|------------|--------|
| ... | ... | ... | HIGH | delete |

## Confirm & Remove (P1)

...

## Right-Size (P2)

...

## Watchlist (P3)

...

## Methodology

- Tool: cloud-cost-cli `scan --provider {provider}`
- Analyzers run: {count from JSON}
- Confidence levels come from the tool, not derived
- Costs are the tool's region-aware estimates

## Cross-Reference

{Issue mode only:}
Findings touching services in `03_ARCHITECTURE.md` for this change:
- {resource}: {note}

## Raw Output

- JSON: `/tmp/cc-scan.json`
- HTML: `/tmp/cc-scan.html`
```

#### 6. Post-Actions

**Issue mode:**

- Append to `.claude/planning/$ISSUE/00_STATUS.md` under `## Artifacts`:
  ```
  - 05f_CLOUD_COST.md — {provider}: ${total}/mo, {P0count} quick wins
  ```
- If the scanned provider is AWS and `/cloud/aws-cost-compare $ISSUE` has NOT been run, suggest it: "AWS detected — run `/cloud/aws-cost-compare $ISSUE` to cross-check against aws-doctor."

**Always:**

- Print report path, provider, and total monthly savings to the user.
- Suggest `/cloud/cost-scan {issue} --provider X` for any other cloud detected in the stack.

### Quality Gates

- `cloud-cost-cli` exited 0
- `--provider` was explicit (not inferred)
- Each finding has a confidence level from the tool (not derived)
- In issue mode, the artifact is linked from `00_STATUS.md`
- If the issue's architecture touches services this scan flagged, that cross-reference is in the report
