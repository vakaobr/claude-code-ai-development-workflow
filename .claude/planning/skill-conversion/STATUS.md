# Skill Conversion Status

**Started:** 2026-04-23
**Source:** `pentest-agent-development/notebooklm-notes/` (41 notes)
**Output:** `.claude/skills/{skill-name}/SKILL.md` (39 skills after SSTI merge)
**Conversion prompt:** `.claude/skills/_shared/batch-conversion-prompt.md` v1.0

## Expected Skill Count

41 source notes → 39 skills (three SSTI notes merge into `ssti-hunter`).
Note: SESSION_CONTEXT.md says "40 skills" — off-by-one; actual math is 41 − 2 = 39.

## Batch Plan

| Batch | Rows (mapping) | Skills |
|---|---|---|
| 1 | 1, 2, 3, 4, 5+8+31 | clickjacking-hunter, xxe-hunter, dom-xss-hunter, idor-hunter, ssti-hunter |
| 2 | 6, 7, 9, 10, 11 | sqli-hunter, aws-iam-hunter, web-recon-active, api-recon, web-recon-passive |
| 3 | 12, 13, 14, 15, 16 | gitlab-cicd-hunter, session-flaw-hunter, csrf-hunter, graphql-hunter, jwt-hunter |
| 4 | 17, 18, 19, 20, 21 | rate-limit-hunter, mass-assignment-hunter, crypto-flaw-hunter, auth-flaw-hunter, business-logic-hunter |
| 5 | 22, 23, 24, 25, 26 | oauth-oidc-hunter, bola-bfla-hunter, command-injection-hunter, ssrf-hunter, xss-hunter |
| 6 | 27, 28, 29, 30, 32 | owasp-api-top10-tester, deserialization-hunter, excessive-data-exposure-hunter, open-redirect-hunter, subdomain-takeover-hunter |
| 7 | 33, 34, 35, 36, 37 | ssrf-cloud-metadata-hunter, path-traversal-hunter, cors-misconfig-hunter, cache-smuggling-hunter, auth-flow-mapper |
| 8 | 38, 39, 40, 41 | attack-surface-mapper, secrets-in-code-hunter, s3-misconfig-hunter, container-hunter |

## Progress Log

<!-- append one line per skill: [NN/39] {skill-name}: done ({words} words, {refs} refs) -->

### Batch 1 (paused for review)

- [01/39] clickjacking-hunter: done (1763 words, 0 refs) — passive profile, T2
- [02/39] xxe-hunter: done (1989 words, 0 refs) — active, T1
- [03/39] dom-xss-hunter: done (1784 words, 0 refs) — active, T1
- [04/39] idor-hunter: done (1915 words, 0 refs) — active, T1
- [05/39] ssti-hunter: done (2055 words, 1 ref) — MERGED from 3 source notes (rows 5+8+31), opus, T1

**Status:** batch 1 approved with two Authorization-Check fixes applied to xxe-hunter and ssti-hunter.

### Batch 2 (paused for review)

- [06/39] sqli-hunter: done (2054 words, 0 refs) — active, T1, opus
- [07/39] aws-iam-hunter: done (2010 words, 0 refs) — cloud-readonly, T3, opus
- [08/39] web-recon-active: done (1772 words, 0 refs) — active, T4, sonnet (service_affecting: true)
- [09/39] api-recon: done (1836 words, 0 refs) — active, T4, sonnet (service_affecting: true)
- [10/39] web-recon-passive: done (1560 words, 0 refs) — passive, T4, sonnet

**Status:** batch 2 approved.

### Batch 3 (paused for review)

- [11/39] gitlab-cicd-hunter: done (1983 words, 0 refs) — cicd-readonly, T3, opus
- [12/39] session-flaw-hunter: done (1966 words, 0 refs) — active, T1, sonnet
- [13/39] csrf-hunter: done (1881 words, 0 refs) — active, T2, sonnet
- [14/39] graphql-hunter: done (2176 words, 0 refs) — active, T1, opus
- [15/39] jwt-hunter: done (2264 words, 0 refs) — active, T1, sonnet

**Status:** batch 3 approved.

### Batch 4 (paused for review)

- [16/39] rate-limit-hunter: done (2144 words, 0 refs) — active, T2, sonnet (service_affecting: true)
- [17/39] mass-assignment-hunter: done (1962 words, 0 refs) — active, T1, sonnet
- [18/39] crypto-flaw-hunter: done (2090 words, 0 refs) — passive, T2, opus (consumes other skills' artifacts)
- [19/39] auth-flaw-hunter: done (2041 words, 0 refs) — active, T1, opus (service_affecting: true, requires security-team notification)
- [20/39] business-logic-hunter: done (2133 words, 0 refs) — active, T1, opus

**Status:** batch 4 approved.

### Batch 5 (paused for review)

- [21/39] oauth-oidc-hunter: done (1997 words, 0 refs) — active, T1, opus
- [22/39] bola-bfla-hunter: done (1885 words, 0 refs) — active, T1, sonnet
- [23/39] command-injection-hunter: done (2076 words, 0 refs) — active, T1, opus (post-RCE halt like ssti)
- [24/39] ssrf-hunter: done (2032 words, 0 refs) — active, T1, opus (gates internal-IP probing on scope)
- [25/39] xss-hunter: done (2065 words, 0 refs) — active, T1, sonnet (stored-XSS cleanup requirement)

**Status:** batch 5 approved.

### Batch 6 (paused for review)

- [26/39] owasp-api-top10-tester: done (1877 words, 0 refs) — active, T1, opus (meta-skill: dispatches to 8 sub-hunters, produces coverage matrix)
- [27/39] deserialization-hunter: done (2039 words, 0 refs) — active, T2, opus (post-RCE halt, harmless-only payloads)
- [28/39] excessive-data-exposure-hunter: done (1974 words, 0 refs) — active, T2, sonnet
- [29/39] open-redirect-hunter: done (1834 words, 0 refs) — active, T2, sonnet (feeds oauth chain targets)
- [30/39] subdomain-takeover-hunter: done (2049 words, 0 refs) — passive, T2, sonnet (detection only, no claim)

**Status:** batch 6 approved.

### Batch 7 (paused for review)

- [31/39] ssrf-cloud-metadata-hunter: done (1962 words, 0 refs) — active, T1, opus (downstream of ssrf-hunter; hands off to aws-iam-hunter)
- [32/39] path-traversal-hunter: done (1965 words, 0 refs) — active, T2, sonnet (post-RCE halt on RFI)
- [33/39] cors-misconfig-hunter: done (1644 words, 0 refs) — passive, T2, sonnet
- [34/39] cache-smuggling-hunter: done (2077 words, 0 refs) — active, T2, opus (staging-only, dual-gated, cleanup verification required)
- [35/39] auth-flow-mapper: done (1939 words, 0 refs) — passive, T4, sonnet (foundational for auth-class hunters)

**Status:** batch 7 approved.

### Batch 8 (final — complete)

- [36/39] attack-surface-mapper: done (1907 words, 0 refs) — active, T4, sonnet (consolidator + prioritizer)
- [37/39] secrets-in-code-hunter: done (1939 words, 0 refs) — repo-readonly, T3, sonnet
- [38/39] s3-misconfig-hunter: done (1811 words, 0 refs) — cloud-readonly, T3, sonnet
- [39/39] container-hunter: done (2179 words, 0 refs) — cloud-readonly, T3, sonnet

**Status:** ALL 39 SKILLS CONVERTED.

---

## Step 3: Validation — PASS

`./scripts/validate-skills.sh` → **0 errors, 0 warnings** across 39 skills.

- Validator updated to exclude pre-existing framework skills (implementing-code, planning-solutions, reviewing-code, review-fix, researching-code, visual-explainer, offensive-security) — those predate the security-skill batch.

## Step 4: Manual spot-check — PASS (4/4)

Sampled: deserialization-hunter (injection), bola-bfla-hunter (access-control), web-recon-passive (recon), s3-misconfig-hunter (cloud). All 4 match the idor-hunter gold-standard template (12 sections, 5-step auth check, 8+ methodology steps, 0 Portuguese leakage).

## Step 4.5: references/ hydration

Agent replaced all 34 stub reference files with real content extracted from the source notes' Sections 5 (PAYLOADS), 8 (REMEDIATION), 3 (DETECTION SIGNALS). Post-extraction validation still 0 errors, 0 warnings.

## Step 5: Integration — applied

`.claude/commands/security.md` patched with `### Delegation Decision` section between Pre-Conditions and Instructions. The `/security` command now delegates to `@security-orchestrator` when scope is large (>3 active assets) OR risk is High OR the user asks for full/deep/comprehensive/orchestrated assessment OR DISCOVERY flags auth / new APIs / uploads / tenant-isolation / 3rd-party integration / crypto-key handling. Otherwise, runs the original OWASP/STRIDE checklist.

---

## Remaining work (gated on user action)

### Step 6: First end-to-end test (user-driven)

**BLOCKED** on `.claude/security-scope.yaml` containing real company assets.

Current state: placeholder assets (`app.internal.example.com`, `api.internal.example.com`, `admin.internal.example.com`, `*.aws-account-12345.s3.amazonaws.com`, `gitlab.internal.example.com`).

Before running E2E, update the scope file with real assets, test credentials, and approved OOB listener host.

Then:
1. User runs `/discover Security assessment of {real-asset}` to create a planning folder
2. User runs `@security-orchestrator {issue-name}`
3. Watch the orchestrator's ASSESSMENT_PLAN.md before approving execution

### Step 7: Cleanup (user-driven, after Step 6 succeeds)

```bash
rm -rf pentest-agent-development/pentest-skills/
rm SESSION_CONTEXT.md
# Keep pentest-agent-development/notebooklm-notes/ (reference)
# Keep pentest-agent-development/source-books/ (reference)
```

Then run `/retro {issue-name}` to capture learnings in CLAUDE.md.

**WORKFLOW COMPLETE — capability shipped. E2E test deferred to first real assessment.**

## Capability-shipping polish

- `.claude/security-scope.yaml` — marked as `⚠ TEMPLATE — REPLACE BEFORE USE`. Placeholder values retained as reference shape; `authorized_by`, `authorization_date`, and `review_date` changed to `REPLACE_ME` / `YYYY-MM-DD` sentinels.
- `.claude/skills/SECURITY_SKILLS_README.md` — navigation entry point for the 39-skill library. Inventory by tier, tool-profile summary, output contract, cross-skill dispatch map, validation command.
- Staging + SESSION_CONTEXT.md cleanup deferred — user to run `rm -rf pentest-agent-development/pentest-skills/` + `rm SESSION_CONTEXT.md` when ready.
