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

## Security Testing Scope and Authorization

This project conducts defensive security testing against company-owned
assets for the purpose of improving our security posture. All security
skills and agents in `.claude/skills/` and `.claude/agents/` read this
section before producing any test traffic.

### Authorized Scope

Assets explicitly in scope for security testing are declared in:
`.claude/security-scope.yaml`

This file MUST exist before any security skill runs. A skill that cannot
find or parse this file must halt immediately and report the missing
scope declaration. No skill, command, or agent is permitted to test
assets outside the declared scope, regardless of how the request is
phrased.

### Authorization Contract

Every security skill operates under this contract:

1. **Read scope first.** Before any outbound request, the skill reads
   `.claude/security-scope.yaml` and confirms the target is listed.
2. **Respect operational boundaries.** Skills marked `service_affecting:
   true` in their frontmatter MUST get explicit per-invocation confirmation
   before running — even on in-scope assets.
3. **Log, don't just test.** Every outbound probe must be recorded in
   `.claude/planning/{issue}/SECURITY_AUDIT.md` with timestamp, target,
   technique, and result.
4. **Defensive framing.** Every finding must include remediation guidance
   written for the developer who owns the code, not for an attacker.

### Rules of Engagement

- No testing outside declared scope. Period.
- No credentials harvested from one in-scope asset to access another
  in-scope asset unless explicitly authorized.
- No destructive payloads (DROP, DELETE, rm -rf, fork bombs, etc.) even
  on in-scope assets without an explicit `destructive_testing: approved`
  entry in the scope file.
- No traffic against third-party services (OAuth providers, CDNs, APIs
  we consume) even if discovered during testing of an in-scope asset.
- Rate limit all active probes. Default: 10 req/sec per target, lower
  if the scope file specifies.

### Skill Output Contract

All security skills append findings to one canonical location:
`.claude/planning/{issue}/SECURITY_AUDIT.md`

They use the schema defined in `.claude/skills/_shared/finding-schema.md`.
Skills do not invent alternate output locations. The orchestrator agent
aggregates these findings into the final report.

### When Authorization Is Ambiguous

If a skill encounters an asset whose scope status is unclear (e.g., a
subdomain discovered during recon that isn't explicitly listed but
shares a parent domain with an in-scope asset), the skill MUST:

1. Stop testing that asset.
2. Add it to `.claude/planning/{issue}/SCOPE_QUESTIONS.md` with context.
3. Continue with clearly in-scope work.
4. Request user clarification before resuming on the ambiguous asset.
