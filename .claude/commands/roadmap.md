---
model: opus
---

## Roadmap — Project Phase Planner

Create or update a project-level **`ROADMAP.md`** that sequences multiple issues into ordered delivery phases. This is the **Spec layer** above per-issue planning: `00_STATUS.md` tracks *one issue's* SDLC phases; `ROADMAP.md` tracks *the project's* phases and which issues belong to each. Context: `$ARGUMENTS`

### When to use
- Starting a multi-issue project and you want a sequenced plan of phases before diving into `/discover`.
- Updating progress as issues complete (`/roadmap update`).
- Before running the autonomous loop (`/roadmap-run {phase}`) — which **requires** a phase with acceptance criteria.

### Instructions

#### 1. Determine Mode
- If `$ARGUMENTS` is empty or `update` → **update mode**: read the existing `ROADMAP.md`, refresh issue statuses (cross-check each member issue's `.claude/planning/{issue}/00_STATUS.md`), archive completed phases to `## Done`.
- Otherwise → **create/extend mode**: treat `$ARGUMENTS` as the project/goal description and decompose it into phases.

#### 2. Decompose into Phases (create/extend)
Break the goal into **ordered, independently shippable phases** (epics). For each phase:
- A one-line **goal**.
- **Acceptance criteria** written as **BDD Given/When/Then** (per the Quality Contract in `CLAUDE.md`). These are what `/roadmap-run` gates each iteration on — they must be concrete and verifiable.
- **Member issues** (kebab-case names; may not exist yet — they're created later via `/discover --roadmap-phase {id}`).
- An **iteration budget** (max autonomous slices before human review) — default 5; raise only with reason.
- **Status**: `pending` | `active` | `complete`.

**Guardrail:** if a phase has **> 8 acceptance criteria**, warn that it's too large and suggest splitting it — large phases defeat the bounded-loop model.

#### 3. Write `ROADMAP.md` (project root)
Use this schema exactly:

```markdown
# Roadmap: {project name}

> Project-level phase plan. Per-issue SDLC status lives in `.claude/planning/{issue}/00_STATUS.md`.
> Autonomous execution: `/roadmap-run {phase-id}` (one bounded slice per call).

## Phase {id} — {goal}
**Status:** pending | active | complete   ·   **Iterations:** {used}/{budget}

### Acceptance Criteria (BDD)
- [ ] Given {context} When {action} Then {outcome}
- [ ] Given … When … Then …

### Issues
- {issue-name} — planned | in-progress | done   (→ `.claude/planning/{issue-name}/`)

---

## Phase {id+1} — {goal}
...

## Done
- ~~Phase {n} — {goal}~~ (completed {date})
```

#### 4. Output to User
Present: the phase list (id, goal, # criteria, budget, status), any "phase too large" warnings, and recommended next steps:
- `/discover {description} --roadmap-phase {id}` to create the first issue under a phase.
- `/roadmap-run {id}` to autonomously execute a phase (only once it has acceptance criteria).

### Quality Gates
- Every phase has a goal, ≥1 BDD acceptance criterion, an iteration budget, and a status.
- Acceptance criteria are concrete/verifiable Given/When/Then (not vague).
- `ROADMAP.md` follows the schema; completed phases archived under `## Done`.
- Two-level integrity: `ROADMAP.md` does not duplicate within-issue SDLC state — it references each issue's planning dir.
- Phases exceeding 8 criteria are flagged for splitting.
