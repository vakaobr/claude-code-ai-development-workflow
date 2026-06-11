# Project Guidelines — Claude Code AI Development Workflow

> **Token-saving note:** Global guidelines (repo types, security, naming, testing, code review) are in `~/CLAUDE.md`. This file contains only project-specific instructions. Reference material: `.claude/QUICK_REFERENCE.md` (tool cheat sheets), `.claude/LEARNINGS.md` (retro learnings).

---

## Project Overview

This repo is a Claude Code SDLC framework: slash commands, skills, agents, and templates that provide a structured DevSecOps development lifecycle. No runtime application code — all artifacts are prompt engineering (`.md` files under `.claude/`).

---

## Development Workflow (DevSecOps SDLC)

Artifacts stored under `.claude/planning/{issue-name}/`, tracked via `00_STATUS.md`.

### Session Start: Incomplete Workflow Detection

Check `.claude/planning/` for directories where `00_STATUS.md` is NOT marked `WORKFLOW COMPLETE`. If found:

> Found {N} incomplete SDLC workflow(s):
> - **{issue-name}** — paused at {phase} (last updated {date})
>
> Run `/sdlc/continue` to resume, or start something new.

### Session Start: Semantic Retrieval Check

If `claude-context` is NOT in `.claude/settings.json` under `mcpServers`, suggest once:

> Semantic code retrieval is not configured. Run `/retrieval/setup` to enable hybrid BM25 + vector search.

### Session Start: Document Conversion Check

If `markitdown` is NOT in `.claude/settings.json` under `mcpServers`, suggest once:

> Document conversion is not configured. Run `/markitdown/setup` to convert PDFs/DOCX/XLSX/etc. to Markdown before reading — saves tokens versus rendering pages as images.

### Quick Start
```bash
/sdlc/continue                       # Resume incomplete workflow
/discover [description]              # Phase 1: Scope + stack detection + repo map
/research {issue-name}               # Phase 2: Deep codebase analysis
/plan {issue-name}                   # Phase 4: Implementation plan
/implement {issue-name}              # Phase 5: Code + tests
/review {issue-name}                 # Phase 6: Code review + QA
/security {issue-name}               # Phase 7a: Static security audit
/hotfix [description]                # Emergency production fix
```

Full command list: run `/COMMAND_USAGE` or see `.claude/QUICK_REFERENCE.md`.

### Issue Name Format
**kebab-case**, 2-5 words, action-prefixed: `add-oauth-auth`, `fix-memory-leak`, `refactor-api-layer`

### Planning Artifacts
```
.claude/planning/{issue-name}/
├── 00_STATUS.md              # Progress tracker (single source of truth)
├── 01_DISCOVERY.md           # Scope, success criteria, detected stack
├── 02_CODE_RESEARCH.md       # Research findings
├── 03_ARCHITECTURE.md        # System design + ADRs
├── 04_IMPLEMENTATION_PLAN.md # Phased implementation strategy
├── 06_CODE_REVIEW.md         # Review findings
├── 07a_SECURITY_AUDIT.md     # Static threat model + OWASP
├── 07b_PENTEST_REPORT.md     # Dynamic pentest results
├── 08_HARDEN_PLAN.md         # Fix plan + regression tests
├── 09_DEPLOY_PLAN.md         # Rollout strategy
├── 10_OBSERVABILITY.md       # Metrics, logging, alerts
└── 11_RETROSPECTIVE.md       # Lessons learned
```

---

## Behavioral Guidelines (project-specific)

- **Workflow tracking**: Use SDLC commands for non-trivial changes to maintain traceability via `00_STATUS.md`
- **README preservation**: When a README exists, patch it — never wipe existing content
- **Learnings**: Full detail → `.claude/LEARNINGS.md`; abbreviated (max 2 recent blocks) → project `CLAUDE.md`
- **Stack auto-detection**: `/discover` scans for languages, frameworks, cloud providers — results in `01_DISCOVERY.md`

---

## Learnings (auto-updated by /retro)
<!-- The /retro command appends lessons learned here. Full history: .claude/LEARNINGS.md -->
<!-- Keep only the 2 most recent retro blocks here; older ones live in .claude/LEARNINGS.md -->

### 2026-03-15 — add-repo-context-engine

- **Embed mandatory workflow tools in existing phase entry points, not as optional standalone commands.** Users follow the happy path — they won't run `/repo-map` manually, but they will run `/discover`.
- **Exclusion lists that exist in multiple prompt files will drift.** Add a cross-reference note pointing to the canonical list. Prevents silent divergence.
- **The Design phase can be skipped for M-sized prompt-only changes; the Observe phase is always skippable for prompt-only changes.**

### 2026-03-15 — add-code-intelligence-layer

- **Template placeholders require a paired generation instruction.** A `## Symbol Index` placeholder in the `01_DISCOVERY.md` template does nothing unless Step 3 explicitly instructs generating the symbol index. Always pair template sections with their generation step.
- **Multi-level activation conditions keep skill pipelines fast on trivial inputs.** Gate expensive steps (`if repo >= 50 files`, `if candidates > 5`) to skip dependency graph and reranking on small repos.
- **The context window IS the intra-session cache.** Don't add `.claude/cache/` directories — ephemeral computation (dependency graph, reranked list) lives in context naturally; only cross-session data (symbol index) needs file persistence.
