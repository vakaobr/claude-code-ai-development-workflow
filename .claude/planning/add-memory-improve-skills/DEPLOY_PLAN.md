# Deploy Plan: add-memory-improve-skills

**When:** 2026-02-28
**Author:** Claude Code (automated)

---

## 1. Pre-Deployment Checklist

| Check | Status | Notes |
|-------|--------|-------|
| All tests pass on CI | N/A | Pure Markdown/YAML project — no CI test suite. Manual verification completed during Review phase (13 automated checks, all PASS). |
| Code review approved | PASS | CODE_REVIEW.md: APPROVED, 0 blocking issues, 23 praise items. |
| Security audit passed | PASS | SECURITY_AUDIT.md: PASSED, 0 findings at all severity levels. |
| Database migrations tested | N/A | No database. |
| Environment variables documented | N/A | No env vars. Memory path is auto-derived by Claude Code from project hash. |
| Feature flags configured | N/A | Configuration project — changes take effect on commit. |
| Monitoring/alerting updated | N/A | No runtime monitoring. Git history provides audit trail. |
| Runbook/playbook updated | PASS | Rollback procedures documented in PROJECT_SPEC.md § Rollback Plan. |
| Stakeholders notified | PENDING | Commit message will serve as notification (repo is developer-facing). |

---

## 2. Rollout Strategy

**Strategy: Big Bang (single commit)**

**Justification:** This is a low-risk change to a pure Markdown/YAML configuration project with:
- No runtime application code
- No APIs, databases, or network components
- No users affected until the commit is merged
- Instant rollback via `git revert`
- All changes verified through 13 automated checks + code review + security audit

### Rollout Plan

| Stage | Action | Verification |
|-------|--------|-------------|
| 1. Stage | `git add` all changed files | `git status` shows correct files |
| 2. Commit | Single commit with descriptive message | Commit succeeds, no hook failures |
| 3. Push | Push to remote main branch | Push succeeds |
| 4. Verify | Clone fresh and test skill loading | Skills resolve, memory files intact |

### Success Criteria to Proceed

- [x] All 5 skill folders exist with valid SKILL.md
- [x] Zero flat .md files remain in `.claude/skills/`
- [x] Zero stale references to old skill paths/names
- [x] Memory files created and under size limits
- [x] `/retro` command has memory write instructions
- [x] README.md and ARCHITECTURE.md updated
- [x] STATE_MANAGEMENT.md archived

---

## 3. ~/.claude Environment Preservation & Migration

This project modifies files in **two locations**: the git repo and `~/.claude/projects/{hash}/memory/`. The deploy must not disturb existing `~/.claude` infrastructure.

### 3a. Inventory of Existing ~/.claude Assets (DO NOT REMOVE)

| Asset | Path | Status | Action |
|-------|------|--------|--------|
| **settings.json** | `~/.claude/settings.json` | Active | PRESERVE — contains permissions (`Read`, `Edit`, `Bash(git *)`, etc.) and `model: opus` preference |
| **MCP Servers** | `~/.claude/claude_desktop_config.json` | Active | PRESERVE — contains `terraform` (Docker-based) and `jira` MCP server configs |
| **Plugins (5 installed)** | `~/.claude/plugins/` | Active | PRESERVE — `code-review`, `github`, `feature-dev`, `atlassian`, `gitlab` (all from `claude-plugins-official`) |
| **Plugin blocklist** | `~/.claude/plugins/blocklist.json` | Active | PRESERVE — 2 entries (test blocklist items) |
| **Global CLAUDE.md** | `~/.claude/CLAUDE.md` | Active | PRESERVE — global user instructions (identical to repo CLAUDE.md but includes Learnings section with INFRA-555 retro) |
| **Session data** | `~/.claude/session-env/`, `history.jsonl`, etc. | Active | PRESERVE — Claude Code internal state |
| **IDE integration** | `~/.claude/ide/` | Active | PRESERVE — IDE plugin configs |

### 3b. Existing Retro Learnings Migration to Memory

The global `~/.claude/CLAUDE.md` contains learnings from a **previous retro (INFRA-555)** that should be migrated into the new memory system for this project's context.

**Source:** `~/.claude/CLAUDE.md` lines 463-472 — 8 learnings from `deploy-n8n-self-hosted`

**Action:** Append these learnings to `memory/learnings.md` so the two-tier memory system captures all historical knowledge:

```markdown
## 2026-02-23 — INFRA-555 (deploy-n8n-self-hosted)
- ECS Fargate pre-start file injection → use init container, not entryPoint override
- Cloudflare DNS pointing to AWS ALB must use proxied=false
- n8n behind TLS-terminating proxy: set N8N_PROTOCOL=http, not https
- n8n RDS SSL: DB_POSTGRESDB_SSL_ENABLED=true + DB_POSTGRESDB_SSL_REJECT_UNAUTHORIZED=false
- RDS CREATE DATABASE OWNER workaround: CREATE then ALTER OWNER
- Terraform SG rule state drift: verify with aws ec2 describe-security-group-rules
- Multi-repo Terraform with separate AWS accounts requires explicit session switching
- Always audit for existing shared resources before provisioning new ones
```

**Also add to `memory/patterns.md`:**

```markdown
## Pattern: Shared Resource Audit Before Provisioning
- Context: When deploying new ECS services or cloud workloads
- Solution: Check for existing shared RDS, ALB, VPC resources before provisioning dedicated ones. Saved ~$48/month on n8n deploy.
- Confirmed: 2026-02-23, INFRA-555
```

### 3c. Deployment Scope — What This Deploy Touches

| Location | What Changes | What Stays |
|----------|-------------|------------|
| **Repo: `.claude/skills/`** | 5 old flat .md deleted, 5 new folders created | Nothing else in `.claude/` touched |
| **Repo: `.claude/agents/`** | `sdlc-orchestrator.md` updated (1 line) | All other agents unchanged |
| **Repo: `.claude/commands/`** | `retro.md` updated, `COMMAND_USAGE.md` updated | All other commands unchanged |
| **Repo: `docs/`** | `integration-plan.md` updated, `archive/` created | All other docs unchanged |
| **~/.claude: `memory/`** | 4 files created (MEMORY.md, patterns.md, decisions.md, learnings.md) | All other `~/.claude/` files untouched |
| **~/.claude: settings.json** | NOT touched | Permissions + model preference preserved |
| **~/.claude: plugins/** | NOT touched | All 5 plugins preserved |
| **~/.claude: MCP config** | NOT touched | Terraform + Jira MCP servers preserved |

### 3d. Security Note

`claude_desktop_config.json` contains a **plaintext Jira API token**. This file is in `~/.claude/` (local only, not in git). No deployment action touches this file, but consider migrating the token to an environment variable or secret manager in a future task.

---

## 4. Database Migration Plan

**N/A** — No database in this project.

---

## 5. Rollback Playbook

### Triggers (when to rollback)

| Trigger | Detection Method |
|---------|-----------------|
| Skills fail to auto-activate from descriptions | Manual test: invoke a prompt that should trigger a skill, skill doesn't load |
| Orchestrator references break | Run `/sdlc` on a test issue, observe "skill not found" errors |
| Memory files cause context bloat | Session startup noticeably slower, or Claude Code warns about context size |
| Cross-references broken | Grep for old paths returns non-zero results |

### Full Rollback Steps

```bash
# 1. Revert the entire commit
git revert HEAD

# 2. Verify old flat skill files are restored
ls .claude/skills/*.md
# Expected: code-research.md, solution-planning.md, code-implementation.md, code-review.md, review-fix.md

# 3. Verify new folders are removed
ls .claude/skills/*/SKILL.md 2>/dev/null
# Expected: no results (or the new folders still exist but aren't used)

# 4. Delete memory files (local only, not in git)
rm -rf ~/.claude/projects/<dashed-project-path>/memory/

# 5. Verify orchestrator is restored
grep "fixing-review-issues" .claude/agents/sdlc-orchestrator.md
# Expected: found (old name restored)

# 6. Functional test
# Start a new Claude Code session and run: /sdlc [test-description]
# Verify all phases complete without "skill not found" errors
```

**Time to rollback:** < 2 minutes (single `git revert` + delete memory directory)

### Partial Rollback: Skills Only

```bash
# Revert only skill-related files
git checkout HEAD~1 -- .claude/skills/
git checkout HEAD~1 -- .claude/agents/sdlc-orchestrator.md
git checkout HEAD~1 -- .claude/ARCHITECTURE.md
git checkout HEAD~1 -- .claude/commands/COMMAND_USAGE.md
git checkout HEAD~1 -- docs/integration-plan.md
git commit -m "Rollback: revert skill migration, keep memory system"
```

### Partial Rollback: Memory Only

```bash
# Delete local memory files
rm -rf ~/.claude/projects/<dashed-project-path>/memory/

# Revert /retro command changes
git checkout HEAD~1 -- .claude/commands/retro.md
git commit -m "Rollback: revert memory system, keep skill migration"
```

### Verification After Rollback

- [ ] `ls .claude/skills/*.md` returns 5 flat files (if full rollback)
- [ ] `ls .claude/skills/*/SKILL.md` returns 5 folder-based skills (if memory-only rollback)
- [ ] Start new Claude Code session — no errors on startup
- [ ] Run a skill-triggering prompt — correct skill activates
- [ ] `grep "fixing-review-issues\|review-fix" .claude/agents/sdlc-orchestrator.md` returns correct name for the rollback state

### Communication

- **Who to notify:** Repository contributors (via commit message / PR description)
- **Status update:** Update STATUS.md to reflect rollback and reason

---

## 6. Post-Deployment Verification

### Immediate Smoke Tests (within 5 minutes)

| Test | Command / Action | Expected Result |
|------|-----------------|-----------------|
| Skill folders exist | `ls .claude/skills/*/SKILL.md` | 5 results |
| No flat files | `ls .claude/skills/*.md 2>/dev/null` | 0 results |
| YAML parses | Read each SKILL.md frontmatter | All 5 parse without error |
| No stale refs | `grep -r "fixing-review-issues" .claude/` | 0 results |
| Memory exists | `ls ~/.claude/projects/*/memory/MEMORY.md` | 1 result |
| Memory under limit | `wc -l < memory/MEMORY.md` | ≤ 200 |

### Functional Tests (within 1 hour)

| Test | Action | Expected Result |
|------|--------|-----------------|
| Skill auto-activation | Type a prompt like "research the codebase for..." | `researching-code` skill activates |
| Orchestrator flow | Run `/sdlc` on a small test issue | All phases complete, correct skills invoked |
| Memory loads on session start | Start new Claude Code session | MEMORY.md content visible in context |
| /retro writes to memory | Run `/retro test-issue` | `learnings.md` updated, MEMORY.md updated |

### 24-Hour Monitoring

| Signal | What to Watch | Threshold |
|--------|---------------|-----------|
| Skill activation rate | Do skills trigger correctly from natural prompts? | ≥ 4/5 skills activate on relevant prompts |
| Memory growth | Does MEMORY.md stay within limits? | ≤ 200 lines after `/retro` runs |
| Session startup | Any errors or warnings on new sessions? | 0 errors |
| Workflow completion | Does full SDLC workflow complete? | All 10 phases accessible |

---

## 7. Communication Plan

### Commit Message

```
Upgrade skills to folder-based format and add two-tier memory system

- Migrate 5 SDLC skills from flat .md to Anthropic official folder-based
  format ({name}/SKILL.md with YAML frontmatter)
- Add two-tier memory system: CLAUDE.md Learnings (repo-shared) +
  auto-memory directory (project-personal)
- Rename fixing-review-issues → review-fix (ADR-001)
- Remove model: sonnet from frontmatter (not in official spec)
- Standardize SKILL.md body: Mindset → Goal → Instructions → Output
  Format → Quality Check → Common Issues
- Update /retro to write to both memory tiers
- Archive STATE_MANAGEMENT.md to docs/archive/
- Update all cross-references (orchestrator, ARCHITECTURE.md,
  COMMAND_USAGE.md, integration-plan.md, README.md)

Files changed: 15 (5 new skills, 4 memory files, 6 updated docs)
Files deleted: 6 (5 old flat skills, 1 archived)

Planning: .claude/planning/add-memory-improve-skills/
```

### Internal Changelog Entry

```markdown
## [2026-02-28] Skills & Memory Upgrade

### Added
- Folder-based skill format (Anthropic official spec) for all 5 SDLC skills
- Two-tier memory system with auto-loaded MEMORY.md and on-demand topic files
- Memory integration in `/retro` command

### Changed
- Skill `fixing-review-issues` renamed to `review-fix`
- Skill descriptions upgraded to [What] + [When] + [Capabilities] pattern
- SKILL.md body standardized to 6-section format

### Removed
- `model: sonnet` field from skill frontmatter
- STATE_MANAGEMENT.md (archived to docs/archive/)
- 5 flat skill .md files (replaced by folder-based equivalents)
```

---

## 8. Deploy Execution Summary

| Step | Action | Risk | Duration |
|------|--------|------|----------|
| 1 | **Pre-flight:** Verify `~/.claude/settings.json`, plugins, MCP configs exist | None | 1 min |
| 2 | **Migrate learnings:** Append INFRA-555 retro learnings to `memory/learnings.md` and pattern to `memory/patterns.md` | None (additive) | 2 min |
| 3 | **Stage repo files:** `git add` all changed/new/deleted files | None | 30 sec |
| 4 | **Commit** with message from section 7 | None | 10 sec |
| 5 | **Push** to remote main branch | Low (revertible) | 10 sec |
| 6 | **Post-flight:** Verify `~/.claude/settings.json`, plugins, MCP configs still intact | None | 1 min |
| 7 | **Smoke tests** from section 6 | None | 5 min |
| 8 | **Functional tests** from section 6 | None | 30 min |
| **Total** | | | ~40 min |

**Risk assessment:** LOW. This is a configuration-only change to a developer-facing repository. No runtime systems are affected. Rollback is a single `git revert`. The `~/.claude` environment (settings, plugins, MCP servers) is explicitly NOT modified by the git commit — only the `memory/` subdirectory is touched (local files, not in git).
