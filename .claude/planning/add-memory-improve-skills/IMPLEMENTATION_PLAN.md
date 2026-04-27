# Implementation Plan: add-memory-improve-skills

## Overview
- **Total Phases:** 4
- **Estimated Effort:** L (significant structural migration + new memory system)
- **Dependencies:** None (all work is within this repo, no external blockers)
- **Feature Flag:** N/A (Markdown/YAML project — phased migration serves same purpose)

## Key References
- `ARCHITECTURE.md` — component design + data model
- `ADR-001` — folder naming (use `name` fields; rename `fixing-review-issues` → `review-fix`)
- `ADR-002` — two-tier memory (CLAUDE.md + auto-memory)
- `PROJECT_SPEC.md` — interface contracts + testing requirements

---

## Phase 1: Create Folder-Based Skills (non-destructive)

### Objective
Create all 5 skill folders with upgraded `SKILL.md` files alongside the old flat files. Old files remain untouched so the system continues working during migration.

### Tasks
- [ ] Task 1.1: Create folder `.claude/skills/researching-code/` and write `SKILL.md` — `.claude/skills/researching-code/SKILL.md`
- [ ] Task 1.2: Create folder `.claude/skills/planning-solutions/` and write `SKILL.md` — `.claude/skills/planning-solutions/SKILL.md`
- [ ] Task 1.3: Create folder `.claude/skills/implementing-code/` and write `SKILL.md` — `.claude/skills/implementing-code/SKILL.md`
- [ ] Task 1.4: Create folder `.claude/skills/reviewing-code/` and write `SKILL.md` — `.claude/skills/reviewing-code/SKILL.md`
- [ ] Task 1.5: Create folder `.claude/skills/review-fix/` and write `SKILL.md` (renamed from `fixing-review-issues`) — `.claude/skills/review-fix/SKILL.md`

**For each SKILL.md, apply these upgrades:**

1. **Remove `model: sonnet`** from YAML frontmatter
2. **Rewrite `description`** to follow `[What] + [When] + [Capabilities]` pattern (under 1,024 chars)
3. **Add `metadata` block** with `version: 1.0.0` and `category: workflow-automation`
4. **Standardize body structure:** Mindset → Goal → Instructions (numbered steps) → Output Format → Quality Check → Common Issues
5. **Preserve all existing procedural content** — restructure, don't rewrite
6. **Ensure `name` field matches folder name exactly**

**Description rewrites (draft):**

| Skill | New `description` |
|-------|-------------------|
| `researching-code` | `Investigates codebase to find minimum context needed for planning. Use when starting a new feature, analyzing unfamiliar code, or preparing for implementation. Identifies files to touch, patterns to follow, and risks to mitigate.` |
| `planning-solutions` | `Creates phased implementation plans with clear scope and acceptance criteria. Use when defining what to build, sequencing work into phases, or establishing validation gates. Produces actionable plans with per-phase validation checklists.` |
| `implementing-code` | `Builds working software by executing implementation plans phase by phase. Use when writing code, running tests, or executing a planned feature build. Implements all phases autonomously, validates each phase, and documents deviations.` |
| `reviewing-code` | `Reviews code for production readiness with focus on blocking issues. Use when performing quality assurance, verifying implementations, or checking security. Runs automated checks, validates plan compliance, and produces APPROVED or NEEDS_FIX verdict.` |
| `review-fix` | `Fixes blocking issues identified during code review to achieve APPROVED status. Use when addressing review feedback or resolving blocking bugs. Applies minimal targeted fixes, re-validates, and iterates up to 3 times.` |

### Tests
- [ ] Verify: All 5 `SKILL.md` files exist — `ls .claude/skills/*/SKILL.md` returns 5 paths
- [ ] Verify: Each YAML frontmatter has `name` and `description`, no `model:` field
- [ ] Verify: Each `name` field matches its parent folder name
- [ ] Verify: Each `description` is under 1,024 characters
- [ ] Verify: Old flat files still exist (not deleted yet) — system still works

### Acceptance Criteria
- 5 new folders exist under `.claude/skills/` with valid `SKILL.md` files
- All YAML frontmatter complies with Anthropic spec (name, description, metadata)
- Old flat `.md` files are UNTOUCHED (coexist during transition)
- Body structure follows standardized template for all 5 skills

### Rollback
- Delete new folders: `rm -rf .claude/skills/researching-code/ .claude/skills/planning-solutions/ .claude/skills/implementing-code/ .claude/skills/reviewing-code/ .claude/skills/review-fix/`
- Old flat files remain — zero impact on existing system

---

## Phase 2: Switch Over — Delete Old Files + Update Cross-References

### Objective
Remove old flat skill files and update all cross-references to reflect the new structure and the `fixing-review-issues` → `review-fix` rename.

### Tasks
- [ ] Task 2.1: Delete old flat skill files — `.claude/skills/code-research.md`, `.claude/skills/solution-planning.md`, `.claude/skills/code-implementation.md`, `.claude/skills/code-review.md`, `.claude/skills/review-fix.md` (the old flat file)
- [ ] Task 2.2: Update orchestrator — rename `fixing-review-issues` to `review-fix` at line 96 — `.claude/agents/sdlc-orchestrator.md`
- [ ] Task 2.3: Update ARCHITECTURE.md — rename `fixing-review-issues` to `review-fix` in skills table (line 81) and visual diagram (lines 35-36) — `.claude/ARCHITECTURE.md`
- [ ] Task 2.4: Update COMMAND_USAGE.md — rename `fixing-review-issues` to `review-fix` at line 100 — `.claude/commands/COMMAND_USAGE.md`
- [ ] Task 2.5: Update docs/integration-plan.md — update skill file path references and rename — `docs/integration-plan.md`
- [ ] Task 2.6: Archive STATE_MANAGEMENT.md — move to `docs/archive/STATE_MANAGEMENT.md` — `.claude/STATE_MANAGEMENT.md` → `docs/archive/STATE_MANAGEMENT.md`

### Tests
- [ ] Verify: No flat `.md` files in `.claude/skills/` — `ls .claude/skills/*.md` returns 0 files
- [ ] Verify: Grep for `fixing-review-issues` across repo returns 0 results (excluding planning artifacts)
- [ ] Verify: Grep for old flat file paths (`skills/code-research.md`, etc.) returns 0 results outside `docs/archive/` and `.claude/planning/`
- [ ] Verify: Orchestrator references all 5 correct skill names
- [ ] Verify: `docs/archive/STATE_MANAGEMENT.md` exists

### Acceptance Criteria
- Old flat skill files are deleted
- `fixing-review-issues` renamed to `review-fix` in all active references
- STATE_MANAGEMENT.md archived
- Zero broken references across the repo

### Rollback
- `git checkout HEAD~1 -- .claude/skills/ .claude/agents/sdlc-orchestrator.md .claude/ARCHITECTURE.md .claude/commands/COMMAND_USAGE.md docs/integration-plan.md .claude/STATE_MANAGEMENT.md`
- Removes new folders: `rm -rf .claude/skills/*/`

---

## Phase 3: Memory System

### Objective
Create the auto-memory directory with structured templates and extend `/retro` to write to both tiers.

### Tasks
- [ ] Task 3.1: Create `MEMORY.md` in auto-memory directory with structured template — `~/.claude/projects/<dashed-project-path>/memory/MEMORY.md`
- [ ] Task 3.2: Create `patterns.md` template — `memory/patterns.md`
- [ ] Task 3.3: Create `decisions.md` template — `memory/decisions.md`
- [ ] Task 3.4: Create `learnings.md` template — `memory/learnings.md`
- [ ] Task 3.5: Seed `MEMORY.md` with project knowledge (SDLC workflow overview, skill format, architecture summary) — `memory/MEMORY.md`
- [ ] Task 3.6: Update `/retro` command to also write to auto-memory (add section after "Update CLAUDE.md") — `.claude/commands/retro.md`

### Tests
- [ ] Verify: `MEMORY.md` exists and is under 200 lines
- [ ] Verify: All 3 topic files exist (`patterns.md`, `decisions.md`, `learnings.md`)
- [ ] Verify: `/retro` command includes auto-memory write instructions
- [ ] Verify: `MEMORY.md` contains structured sections (Quick Reference, Key Patterns, Decisions, Lessons, Session Notes)

### Acceptance Criteria
- Auto-memory directory has 4 files: MEMORY.md + 3 topic files
- MEMORY.md is seeded with project knowledge (not empty templates)
- MEMORY.md is ≤ 200 lines
- `/retro` command instructs writing to both CLAUDE.md and auto-memory

### Rollback
- Delete memory files: `rm -rf ~/.claude/projects/<dashed-project-path>/memory/`
- Revert retro: `git checkout HEAD~1 -- .claude/commands/retro.md`

---

## Phase 4: Documentation Updates

### Objective
Update all documentation to reflect the new skill format and memory system. Final cross-reference audit.

### Tasks
- [ ] Task 4.1: Update `.claude/ARCHITECTURE.md` — add memory layer to visual diagram, update skills section to show folder format, add memory component description — `.claude/ARCHITECTURE.md`
- [ ] Task 4.2: Patch `README.md` — add Skills Format section explaining folder-based skills, add Memory System section — `README.md`
- [ ] Task 4.3: Final cross-reference audit — grep for any remaining old paths or names — all files
- [ ] Task 4.4: Update planning STATUS.md — mark all completed phases — `.claude/planning/add-memory-improve-skills/STATUS.md`

### Tests
- [ ] Verify: ARCHITECTURE.md mentions memory system and folder-based skills
- [ ] Verify: README.md contains skills format and memory sections
- [ ] Verify: Grep for old flat file names (`code-research.md`, `solution-planning.md`, `code-implementation.md`, `code-review.md`) returns 0 results in active files
- [ ] Verify: STATUS.md shows Implementation as completed

### Acceptance Criteria
- All documentation reflects current state (folder-based skills + memory)
- No stale references to old file structure
- README.md patched (not rewritten)

### Rollback
- `git revert` the documentation commit
- No runtime impact (documentation only)

---

## Test Strategy

### Structure Validation (Phase 1-2)
- **Coverage target:** 100% of skill files
- **Key checks:** YAML parsing, name-folder match, description length, body structure, no `model:` field
- **Method:** Grep + Read + character/word counts on each SKILL.md

### Cross-Reference Integrity (Phase 2)
- **Coverage target:** 0 broken references
- **Key checks:** Old file paths, old skill names (`fixing-review-issues`), orchestrator references
- **Method:** Repo-wide grep for old paths and names; read each cross-reference file to verify

### Memory System (Phase 3)
- **Coverage target:** All 4 memory files exist with valid content
- **Key checks:** File existence, MEMORY.md line count ≤ 200, structured sections present
- **Method:** Read + line count + section header grep

### End-to-End (Post Phase 4)
- **Coverage target:** Full workflow functional
- **Key checks:** Skills trigger from descriptions, `/retro` writes to memory, no regressions
- **Method:** Manual invocation of workflow commands on a test issue

### Performance (Non-Functional)
- **Baseline:** Estimate token overhead from skill frontmatters + MEMORY.md
- **Target:** < 4,000 tokens total added to context per session
- **Method:** Character count → token estimate (1 token ≈ 4 chars)
