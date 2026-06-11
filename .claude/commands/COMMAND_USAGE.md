# Command Usage Reference

Quick reference for the SDLC workflow.

## `/sdlc <issue-name> [description] [flags]`

Execute complete SDLC: Research → Plan → Implement → Review

### Syntax

```bash
/sdlc <issue-name> [description] [--resume | --plan | --implement | --review]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `issue-name` | Yes | Kebab-case identifier (1-50 chars) |
| `description` | No* | What to build (max 1000 chars) |
| `--resume` | No | Continue from STATUS.md |
| `--plan` | No | Start from Planning (needs RESEARCH.md) |
| `--implement` | No | Start from Implementation (needs PLAN.md) |
| `--review` | No | Start from Review (needs IMPLEMENTATION.md) |

*Required for new workflows

### Examples

```bash
# Full workflow
/sdlc add-oauth-auth Implement OAuth2 with Google

# Resume after interruption
/sdlc add-oauth-auth --resume

# Start from specific phase
/sdlc add-oauth-auth --plan
```

### What It Creates

```
docs/{issue-name}/
├── STATUS.md           # Progress tracker
├── RESEARCH.md         # What we found
├── PLAN.md             # What we'll build
├── IMPLEMENTATION.md   # What we built
└── REVIEW.md           # Is it ready?
```

### Issue Name Format

- Kebab-case: `add-oauth-auth`
- 1-50 characters
- No path traversal

**Good:**
- `add-oauth-auth`
- `fix-memory-leak`
- `refactor-api-layer`

**Bad:**
- `AddOAuthAuth` (not kebab-case)
- `fix` (too vague)
- `../etc/passwd` (path traversal)

### Check Progress

```bash
cat docs/{issue-name}/STATUS.md
```

---

## Workflow Phases

| Phase | Creates | Gate |
|-------|---------|------|
| Research | RESEARCH.md | 3 questions answered |
| Planning | PLAN.md | Scope + phases + criteria |
| Implementation | IMPLEMENTATION.md + code | All phases done + tests pass |
| Review | REVIEW.md | APPROVED verdict |
| Fix | Fixed code | Blocking issues resolved |
| Security (7a) | 07a_SECURITY_AUDIT.md | OWASP/STRIDE evaluated |
| Pentest (7b) | 07b_PENTEST_REPORT.md | Shannon run complete |
| AI Audit (7c) | 07c_AI_THREAT_MODEL.md | LLM threats documented |
| Harden (8) | 08_HARDEN_PLAN.md + patches | P0 fixes implemented |

---

## Roadmap & Loop (project-level)

The framework reads as four **Delivery Layers** (Spec / Verifier / Loop / Environment — see `.claude/ARCHITECTURE.md`). Two commands operate *above* a single issue:

### `/roadmap [description | update]`
Spec layer. Creates/updates a project-root `ROADMAP.md` that sequences issues into ordered phases, each with a goal, **BDD acceptance criteria**, member issues, status, and an **iteration budget**. Attach a new issue to a phase with `/discover {desc} --roadmap-phase {id}`.

### `/roadmap-run {phase-id}`
Loop layer. Executes **one bounded slice** of a roadmap phase, then stops and reports. Repeat it (or wrap with native `/loop /roadmap-run {id}`) until done.
- **Hard stops:** all criteria met (`✅ COMPLETE`) · iteration budget reached (`⛔ BUDGET`) · no criteria defined (refuse).
- **Delegates** per issue to `/sdlc` / `/implement` (never reimplements the SDLC).
- **Confirms** before commits, issue creation, and any destructive op. On a bug → regression test + tracked issue.
- Two-level model: `sdlc-orchestrator` = one issue (`STATE.json`); `/roadmap-run` = one roadmap phase (`ROADMAP.md`).

---

## `/sdlc/continue`

Resume the most recent incomplete SDLC workflow.

```bash
/sdlc/continue
```

**What it does:**
1. Scans `.claude/planning/` for incomplete workflows
2. If one found, auto-selects it
3. If multiple found, asks you to choose
4. Determines the next phase from `00_STATUS.md`
5. Invokes the appropriate command

**When to use:**
- Starting a new Claude session with unfinished work
- After a session timeout or interruption
- When you can't remember which phase you were on

---

## Security Commands (DevSecOps)

### `/security/pentest {issue}`

Phase 7b — Dynamic pentest via Shannon (autonomous AI pentester).

```bash
/security/pentest add-jwt-rbac
```

**Prerequisites:** `/security` completed, staging running, Docker available, Shannon cloned.
**Output:** `07b_PENTEST_REPORT.md` with proven exploits only.

> Never run against production. Staging or localhost only.

### `/security/redteam-ai {issue}`

Phase 7c — AI/LLM threat modeling (only if LLMs in stack).

```bash
/security/redteam-ai add-chat-assistant
```

**Skip if** no LLM/AI components. **Output:** `07c_AI_THREAT_MODEL.md`.

### `/security/harden {issue}`

Phase 8 — Aggregate findings, prioritize, and implement fixes.

```bash
/security/harden add-jwt-rbac
```

**Priority:** P0 (fix now) → P1 (this sprint) → P2 (next sprint) → P3 (backlog).
**Output:** `08_HARDEN_PLAN.md` + P0 patches applied + GitHub issues for P1/P2.

---

## n8n Workflow Automation

### `/n8n/setup`

Interactive setup wizard for n8n-MCP integration.

```bash
/n8n/setup
```

**What it does:**
1. Checks if n8n-MCP is already configured
2. Asks hosting preference: hosted service, npx, Docker, or local dev
3. Asks capability level: basic (docs only) or full (instance management)
4. Collects n8n API URL + key (full mode only)
5. Updates `.claude/settings.json` with MCP server config
6. Optionally disables telemetry

**Hosting options:**

| Option | Requirements | Best For |
|--------|-------------|----------|
| Hosted service | None | Quick start, no infra |
| npx (recommended) | Node.js 18+ | Most users |
| Docker | Docker installed | Isolated environments |
| Local dev | Clone + build | Contributors |

### `/n8n [request]`

Work with n8n — search nodes, browse templates, build & manage workflows.

```bash
/n8n search for Slack nodes
/n8n how does the HTTP Request node work
/n8n find templates for email automation
/n8n create a workflow that posts GitHub issues to Slack   # full mode
/n8n show all my active workflows                          # full mode
```

**Requires:** `/n8n/setup` completed first. If not configured, prompts to run setup.

**Basic mode tools:** search_nodes, get_node, validate_node, validate_workflow, search_templates, get_template
**Full mode adds:** list/create/update/delete/trigger workflows, list/get executions

---

## Architecture

```
/sdlc command
    ↓
SDLC Orchestrator Agent
    ↓
Skills (sequential):
  • researching-code
  • planning-solutions
  • implementing-code
  • reviewing-code
  • review-fix (if needed)
    ↓
Security Layer:
  • /security (7a: static)
  • /security/pentest (7b: dynamic, optional)
  • /security/redteam-ai (7c: AI audit, optional)
  • /security/harden (8: fix loop)
    ↓
5 core artifacts + security artifacts + code
```

---

## Benefits

- **Single command** - Full SDLC in one invocation
- **Autonomous** - No manual commands between phases
- **Organized** - All artifacts in one directory
- **Tracked** - STATUS.md shows progress
- **Quality gates** - Validation at each phase
- **Self-healing** - Auto fix loop (max 3)
- **DevSecOps** - Integrated security testing with proven exploits only
