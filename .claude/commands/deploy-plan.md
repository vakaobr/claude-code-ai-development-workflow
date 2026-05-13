---
model: sonnet
---

## Phase 8: Deployment Strategy

You are entering the **Deploy** phase for issue: `$ARGUMENTS`

### Pre-Conditions
- Read `00_STATUS.md` — confirm Security audit is complete
- Read `03_ARCHITECTURE.md` for infrastructure context
- Read `03_PROJECT_SPEC.md` for non-functional requirements

### Instructions

Create a deployment strategy. Produce `.claude/planning/$ARGUMENTS/09_DEPLOY_PLAN.md`:

#### 1. Pre-Deployment Checklist

- [ ] All tests pass on CI
- [ ] Code review approved
- [ ] Security audit passed
- [ ] Database migrations tested (if any)
- [ ] Environment variables documented and configured
- [ ] Feature flags configured (if applicable)
- [ ] Monitoring/alerting updated (from /observe phase or planned)
- [ ] Runbook/playbook updated
- [ ] Stakeholders notified
- [ ] **Cost impact captured** — required if the change provisions cloud resources:
  - AWS: `/cloud/aws-cost-estimate $ARGUMENTS` (and optionally `/cloud/aws-cost-compare $ARGUMENTS` for a second-tool cross-check)
  - Azure: `/cloud/cost-scan $ARGUMENTS --provider azure --location {region}`
  - GCP: `/cloud/cost-scan $ARGUMENTS --provider gcp --region {region}`

#### 1a. Cost Impact (cloud-provisioning changes)

The expected cost artifacts per provider are:

| Provider | Required Artifact |
|----------|-------------------|
| AWS | `.claude/planning/$ARGUMENTS/05c_COST_BASELINE.md` |
| Azure / GCP | `.claude/planning/$ARGUMENTS/05f_CLOUD_COST.md` |

If the change provisions cloud resources and the matching artifact does NOT exist:

1. Suggest the user run the appropriate command from the checklist above.
2. If they decline (or the change is non-cloud), record the reason in this plan under a `## Cost Impact` section: "N/A — non-cloud change" or "Skipped — {reason}".

If the artifact exists, embed its monthly delta / savings figure into `09_DEPLOY_PLAN.md` under `## Cost Impact`, with a link back to the source doc. Flag the deploy as **Cost-Material** if the projected monthly delta exceeds 10% of current account spend (or if any single Consensus finding from `05g_AWS_COMPARE.md` exceeds $500/mo).

#### 2. Rollout Strategy

Choose and detail the appropriate strategy:

| Strategy | When to Use |
|----------|-------------|
| **Big Bang** | Low-risk, simple changes |
| **Feature Flag** | High-risk, needs gradual rollout |
| **Canary** | Performance-sensitive, needs production validation |
| **Blue-Green** | Zero-downtime required |
| **Rolling** | Stateless services, gradual replacement |

Detail:
- Rollout percentage stages (e.g., 1% → 10% → 50% → 100%)
- Duration at each stage
- Success criteria to proceed to next stage
- Monitoring signals to watch at each stage

#### 3. Database Migration Plan (if applicable)

- Migration scripts and their order
- Backwards compatibility during rollout
- Data backfill strategy (if needed)
- Estimated migration duration
- Rollback migration scripts

#### 4. Rollback Playbook

```markdown
## Rollback Procedure

### Triggers (when to rollback)
- Error rate exceeds {threshold}
- Latency exceeds {threshold}
- {specific business metric} degrades by {amount}

### Steps
1. {step 1}
2. {step 2}
3. ...

### Verification
- How to confirm rollback was successful
- Data consistency checks after rollback

### Communication
- Who to notify
- Status page update template
```

#### 5. Post-Deployment Verification

- Smoke tests to run immediately after deploy
- Health check endpoints to monitor
- Key metrics to watch for 24 hours
- User-facing functionality to manually verify

#### 6. Communication Plan

- Changelog entry draft
- Internal team notification
- User-facing release notes (if applicable)

### Post-Actions
- Update `00_STATUS.md`: mark Deploy as completed (planned)
- Suggest next command: `/observe $ARGUMENTS`

### Quality Gates
- Rollout strategy is specific (not just "deploy to production")
- Rollback playbook has concrete steps (not "revert the deploy")
- Success criteria are measurable
- Pre-deployment checklist references actual commands/tools
