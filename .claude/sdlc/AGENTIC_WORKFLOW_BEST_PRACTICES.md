# Agentic SDLC Workflow — Expert Review & Best Practices Guide

**Audience:** Agents, architects, and engineers implementing autonomous SDLC pipelines with Claude Code
**Scope:** Full lifecycle review of the Research → Architecture → Plan → Implement → Review → Docs pipeline
**Model Reference:** Claude Sonnet 4.6 / Opus 4.6 / Haiku 4.5 (2026)

---

## Executive Summary

This workflow is architecturally sound and implements the right patterns for autonomous SDLC orchestration with Claude Code. The core design — isolated agent contexts, parallel expert review, scoped fix loops, and STATE.json as the single source of truth — reflects 2026 best practices. Several issues need attention before this can be considered truly production-grade at enterprise scale.

**Verdict:** Strong foundation. Eight specific fixes required. Seven improvements recommended.

---

## Architecture Assessment

### What This Workflow Does Well

#### 1. Agent Isolation via the Agent Tool (Critical Pattern)

Every phase spawns a fresh Agent subagent with its own 200K context window. This is the most important architectural decision in the workflow and it is correct.

**Why it matters:** Without isolation, the orchestrator's context grows with every phase. By the time you reach the review phase, the orchestrator context contains research findings, architecture decisions, the full plan, and all implementation output — often exceeding the context window and causing hallucination or truncation. Isolation prevents this entirely.

**Rule for agents:** Never run phase logic inline in the orchestrator. Always delegate to a subagent via `Agent(prompt: "Follow .claude/agents/{agent}.md ...")`.

#### 2. Parallel Expert Review (Performance Pattern)

Security, QA, and SRE reviewers spawn simultaneously in a single orchestrator response. This cuts review time by ~66% compared to sequential review and is the correct pattern for independent experts.

**Rule for agents:** Any set of agents that produce independent outputs from the same inputs should be spawned in parallel — in a single response with multiple `Agent()` calls. Never spawn independent reviewers sequentially.

#### 3. Scoped Fix Loop (Efficiency Pattern)

The `failing_experts` array in STATE.json tracks which reviewers returned `NEEDS_FIX`. Only those reviewers re-run after a fix iteration. If security approved but QA failed, security does not re-review after the fix — it stays approved.

**Why this is right:** Re-running all reviewers on every fix is wasteful and can cause approval drift (a reviewer that passed might flag new issues in unchanged code). Scoped re-review is deterministic and efficient.

**Rule for agents:** Maintain a `failing_experts` list. On each fix iteration, re-spawn only the agents in that list.

#### 4. STATE.json as Machine State, STATUS.md as Human State

Two artifact types serve different consumers:
- `STATE.json` — machine-readable, schema-validated, drives `--resume` logic
- `STATUS.md` — human-readable, markdown checkboxes, drives user communication

**Rule for agents:** Never parse STATUS.md for resume logic. Never write machine state (phase transitions, verdicts) into STATUS.md. The schema boundary between human and machine state must be enforced.

#### 5. Single Artifact Owner (DRY Pattern)

Each output file is written by exactly one agent. No two agents write to the same file. This prevents merge conflicts and ensures each agent has full ownership and accountability for its output.

**Rule for agents:** Define exactly one writer per artifact in the workflow design. If two agents need to update the same file, use a handoff pattern: one agent creates, another appends to a clearly defined section.

#### 6. Verified Validation (Evidence Pattern)

The implementation agent is prohibited from claiming tests pass. It must run validation commands via `Bash` and capture actual output in `IMPLEMENTATION.md`. This evidence is then available to reviewers.

**Rule for agents:** Claims are not evidence. Any agent asserting that validation passed must capture and include the actual command output. "Tests pass" without output is a blocking issue.

#### 7. Tool Discipline (Security Pattern)

Every agent has explicit tool rules: use `Read` not `cat`, `Glob` not `find`/`ls`, `Grep` not `grep`/`rg`, `Write`/`Edit` not `echo`/`sed`/`awk`. Reserve `Bash` for build tools, tests, and git.

**Why this matters:** Native Claude Code tools have managed permissions and proper access control. Using `Bash` for file operations bypasses these controls and introduces potential command injection vectors. Native tools also provide better audit trails.

#### 8. Right-Sized Model Assignment

| Phase | Model | Rationale |
|-------|-------|-----------|
| Command parsing | Haiku 4.5 | Parse only — no reasoning needed, minimize cost |
| Orchestration | Opus 4.6 | Coordinates complex state, makes phase transitions |
| Architecture | Opus 4.6 | Non-obvious design decisions require best reasoning |
| Planning | Opus 4.6 | Scope definition and risk assessment benefit from strong reasoning |
| Research | Sonnet 4.6 | Codebase exploration — good at pattern recognition |
| Implementation | Sonnet 4.6 | Code generation at scale — excellent capability |
| Security Review | Opus 4.6 | Threat modeling requires adversarial reasoning |
| QA Review | Sonnet 4.6 | Test coverage analysis — systematic, not creative |
| SRE Review | Sonnet 4.6 | Operational checklist — systematic, not creative |
| Fix | Sonnet 4.6 | Targeted code changes — no complex reasoning needed |
| Tech Writer | Sonnet 4.6 | Documentation generation — well-suited |

This model map is close to optimal. See issue #3 below for one adjustment.

---

## Critical Issues (Must Fix)

### Issue 1: settings.json Grants Insufficient Permissions for Autonomous Operation

**Current state:**
```json
{
  "permissions": {
    "allow": ["Write", "Edit"]
  }
}
```

**Problem:** The orchestrator and all subagents require `Read`, `Bash`, `Glob`, `Grep`, `Write`, `Edit`, and `Agent` to operate autonomously. With only `Write` and `Edit` in the allow list, every `Read`, `Bash`, `Glob`, and `Grep` call prompts the user for permission approval. This breaks autonomous operation completely.

**Fix:**
```json
{
  "permissions": {
    "allow": [
      "Read",
      "Write",
      "Edit",
      "Glob",
      "Grep",
      "Bash(git diff*)",
      "Bash(git log*)",
      "Bash(git status*)",
      "Bash(npm test*)",
      "Bash(npm run*)",
      "Bash(npx tsc*)",
      "Bash(pytest*)",
      "Bash(go test*)",
      "Bash(npm audit*)",
      "Bash(pip-audit*)",
      "Agent"
    ]
  }
}
```

**Why scoped Bash patterns:** Rather than allowing all Bash, scope each allowed command. This prevents agents from accidentally running destructive commands (`rm -rf`, `git reset --hard`, `git push --force`) without user confirmation. The narrow allow list is the enterprise-safe approach.

---

### Issue 2: The /sdlc Command Missing the Agent Tool

**Current state:** The `sdlc.md` command declares `tools: [Read, Write, Glob]`. It tells Haiku to "INVOKE AGENT: .claude/agents/sdlc-orchestrator.md" but Haiku cannot do this without the `Agent` tool.

**Problem:** In Claude Code, invoking a subagent from a slash command requires the `Agent` tool to be available in that command's tool list. Without it, the invocation instruction is a no-op or degrades to inline execution by Haiku (which lacks the orchestrator's toolset and model).

**Fix:** Add `Agent` to the sdlc.md command tools:
```yaml
tools:
  - Read
  - Write
  - Glob
  - Agent
```

---

### Issue 3: Orphaned sdlc-code-review Skill

**Current state:** `.claude/skills/sdlc-code-review.md` exists but is never referenced in the orchestrator, CLAUDE.md, or any agent. The three expert reviewer agents (security, QA, SRE) handle all review responsibility.

**Problem:** An unreferenced skill creates confusion about the workflow. Future agents or contributors might invoke it, duplicating or conflicting with the expert review phase.

**Fix:** Delete `.claude/skills/sdlc-code-review.md` or move its useful content into the individual reviewer agents. Document the deletion in CLAUDE.md.

---

### Issue 4: STATE.json risk_level Never Updated After Research

**Current state:** STATE.json initializes with `"risk_level": "Unknown"`. The research agent writes risk level to RESEARCH.md ("Risk: Low/Medium/High") but the orchestrator never reads this back and updates STATE.json.

**Problem:** The risk level in STATE.json remains "Unknown" through the entire workflow. The Production Readiness gate checks STATE.json, so it always reports "Unknown" risk. Resume logic cannot use risk level for routing decisions. Documentation agents cannot surface the correct risk level.

**Fix:** After the Research phase completes, the orchestrator should read RESEARCH.md, extract the risk level, and update STATE.json:
```json
"metadata": {
  "description": "...",
  "risk_level": "Medium"
}
```

---

### Issue 5: Fix Loop Doesn't Update IMPLEMENTATION.md

**Current state:** When the fix loop runs, the fix agent updates REVIEW.md (strikethrough fixed items) and STATUS.md. IMPLEMENTATION.md is not updated.

**Problem:** The Documentation phase reads IMPLEMENTATION.md for "Files Created" and "Files Modified" lists. After fix iterations, additional files may have been modified that aren't in IMPLEMENTATION.md. The tech writer produces inaccurate documentation as a result.

**Fix:** The fix agent (sdlc-review-fix.md) must append a "Fix Iteration {N}" section to IMPLEMENTATION.md listing:
- Additional files modified
- What was changed and why
- Updated test output

Alternatively, the tech writer should always run `git diff HEAD --name-only` as its primary source of changed files, using IMPLEMENTATION.md only as supplementary context.

---

### Issue 6: Review Agents Use git diff HEAD on Uncommitted Changes

**Current state:** Review agents run `git diff HEAD --name-only` to identify changed files.

**Problem:** `git diff HEAD` shows the diff between HEAD and the working tree. If the implementation ran without committing, all changes are untracked working tree changes — this command does correctly show them. However, the security reviewer also uses `git diff HEAD` to get the actual diff content for STRIDE analysis. The working tree diff may be very large (entire implementation) and is more useful as staged/structured than as a raw diff.

**Best practice fix:** Implementation should stage changes (`git add -A`) after completing all phases so that `git diff --cached` provides a clean, staged view of exactly what will be committed. Review agents can then use `git diff --cached --name-only` for structured review. Add a gate in the orchestrator after implementation: verify that `git diff --cached` is non-empty before spawning reviewers.

---

### Issue 7: No Pre-Flight Checks Before Workflow Start

**Current state:** The orchestrator immediately creates the docs directory and writes STATE.json on invocation with no environment validation.

**Problem:** Several silent failure modes exist:
- A conflicting STATE.json from a previous run in `complete` state triggers "already complete" but the issue might have regressed
- No validation that required tools exist (`npm`, `python`, `go`, etc.)
- No check that the working tree is clean before starting (uncommitted unrelated changes will contaminate the review agents' `git diff` output)
- No check that the user-provided description is meaningful (empty string causes a no-op research phase)

**Fix:** Add a pre-flight check at orchestrator initialization:
```
1. If STATE.json exists and current_phase = "complete": warn user, require --force to re-run
2. If STATE.json exists and current_phase != "complete" and --resume not passed: warn user
3. Check git status: if uncommitted changes exist, warn user (don't block, but surface it)
4. Verify description is non-empty (Haiku can catch this in the command)
```

---

### Issue 8: EnterPlanMode in Subagent Context Has No UX Effect

**Current state:** The solution-planning skill calls `EnterPlanMode` before drafting and `ExitPlanMode` after. However, this skill runs as a subagent spawned by the orchestrator.

**Problem:** `EnterPlanMode`/`ExitPlanMode` signals are only meaningful in the main conversation context. When called inside a subagent, they have no observable effect on the main conversation UI. The user never sees the plan for review before implementation proceeds.

**Impact:** The planning phase is supposed to surface the plan to the user for review (a human-in-the-loop checkpoint). This checkpoint is silently bypassed in the current architecture.

**Fix options:**
1. **Recommended:** After the Planning phase completes, the orchestrator reads PLAN.md and presents it to the user with a confirmation prompt before spawning the Implementation agent. This restores the human checkpoint at the orchestrator level.
2. Move PlanMode into the orchestrator itself when it presents the planning phase output.

---

## Improvements (Should Fix)

### Improvement 1: Human Approval Checkpoint for High-Risk Features

After the Research phase, if `risk_level = "High"`, pause and ask the user to confirm before proceeding to architecture and planning. High-risk features touch shared infrastructure, authentication, data migrations, or public APIs. Human review of the research findings before implementation begins prevents wasted effort.

**Pattern:**
```
After Research:
  IF risk_level == "High":
    Present RESEARCH.md summary
    Ask: "Risk level is High. Review the research findings and confirm to proceed."
    Wait for user confirmation
  ELSE:
    Auto-proceed
```

---

### Improvement 2: Feature Branch Strategy

**Current state:** All workflow changes are made directly on whatever branch the user has checked out (typically `main`).

**Problem:** For enterprise use, work on `main` directly is risky. Any partial implementation or failed fix loop leaves `main` in a broken state.

**Recommended pattern:**
```
On workflow start (not --resume):
  Create branch: git checkout -b feature/{issue_name}

On completion (PRODUCTION_READY):
  Present branch name and suggest: git push -u origin feature/{issue_name}
  Include PR template in the suggested commit message
```

Note: Per current project configuration, worktrees are NOT to be used. Standard branch creation with `git checkout -b` is the correct approach.

---

### Improvement 3: Partial Approval Persistence Across Fix Iterations

**Current state:** The `failing_experts` list correctly tracks who failed. But there's a subtle issue: the `REVIEW.md` is recreated each iteration by the orchestrator reading the three expert files. If an expert approved in iteration 1 and isn't re-run in iteration 2, their artifact (e.g., `SECURITY.md`) still correctly shows "APPROVED" — this is correct behavior.

**Improvement:** Make the approval persistence more explicit in the orchestrator's REVIEW.md aggregation. When building the REVIEW.md after a fix iteration, show:

```markdown
| Expert | Status | Iteration Approved |
|--------|--------|--------------------|
| Security | ✓ APPROVED | Iteration 1 |
| QA | ✓ APPROVED | Iteration 2 (was NEEDS_FIX) |
| SRE | ✓ APPROVED | Iteration 1 |
```

This audit trail shows exactly when each expert approved, which is valuable for retrospectives and compliance.

---

### Improvement 4: Retrospective Structured Data

**Current state:** RETROSPECTIVES.md is a free-text markdown log.

**Problem:** Free-text retrospectives can't be queried. "Which features required 3 fix iterations?" requires reading every entry. For teams running many workflows, aggregate analysis becomes manual.

**Recommended format:**
```markdown
## {issue_name} — {date}

```json
{
  "issue_name": "...",
  "date": "...",
  "fix_iterations": N,
  "blocked": false,
  "expert_failures": ["qa"],
  "total_phases": 7,
  "risk_level": "Medium"
}
```

**Narrative:**
- **What slowed things down:** {observation}
- **Suggested improvement:** {concrete suggestion}

---
```

The JSON block allows future agents to parse and aggregate retrospective data.

---

### Improvement 5: Architecture Phase YAGNI Gate

**Current state:** The orchestrator tells the Architecture agent: "The ADR.md must always be created." Even for trivial changes, the architecture phase runs.

**Improvement:** Apply a YAGNI gate at the orchestrator level before spawning the Architecture agent:

```
After Research, if RESEARCH.md contains:
  - "Risk: Low"
  - "Approach: follows existing {pattern} pattern"
  - No new dependencies
  - No new external services

Then: create a minimal ADR.md inline (no agent spawn needed):
  "No architectural decision required. Follows existing patterns."
  Update STATE.json and proceed to Planning.
```

This saves one agent spawn (and its token cost) for routine features.

---

### Improvement 6: Token Budget Awareness

**Current state:** No token budget tracking or cost awareness.

**Improvement:** The orchestrator should track approximate token cost in STATE.json:

```json
"metadata": {
  "description": "...",
  "risk_level": "Medium",
  "estimated_cost_usd": 0.85,
  "phases_cost": {
    "research": 0.12,
    "architecture": 0.18,
    "planning": 0.15,
    "implementation": 0.28,
    "review": 0.12
  }
}
```

This is approximate (based on known per-token pricing for each model) but gives teams visibility into workflow cost — critical for enterprise adoption and optimization.

---

### Improvement 7: Dependency Injection Between Phases

**Current state:** Each phase agent is told "Read docs/{issue_name}/RESEARCH.md" in its prompt. The agent must independently find and read these files.

**Improvement:** The orchestrator should pass a concise summary of key prior phase outputs directly in the agent prompt. This ensures critical context is front-loaded in the agent's context window, not buried in a file read:

```
Agent(
  prompt: "
    Execute the Implementation phase for {issue_name}

    === KEY CONTEXT (from prior phases) ===
    Risk level: Medium
    Files to touch: src/auth/google.ts (new), src/routes/auth.ts (modify)
    Key pattern: Follow OAuth strategy pattern from src/auth/github.ts
    Architectural constraint: Use existing session middleware, do not introduce new session storage
    === END KEY CONTEXT ===

    Read docs/{issue_name}/PLAN.md for full details.
    Follow ALL instructions in .claude/skills/sdlc-code-implementation.md
    ...
  "
)
```

Front-loading context reduces the chance of an agent missing a critical constraint that's buried in a large RESEARCH.md or ADR.md.

---

## 2026 Claude Code Best Practices Reference

### Agent Tool Patterns

**Pattern: Parallel independent agents**
```
# Correct — parallel in one response
Agent(prompt: "Security review..."),
Agent(prompt: "QA review..."),
Agent(prompt: "SRE review...")

# Wrong — sequential
Agent(prompt: "Security review...")  # wait
Agent(prompt: "QA review...")        # wait
Agent(prompt: "SRE review...")
```

**Pattern: Orchestrator never does phase work inline**
```
# Correct — delegate to subagent
Agent(prompt: "Follow .claude/skills/sdlc-code-implementation.md ...")

# Wrong — orchestrator implements directly
[orchestrator writes code, runs tests itself]
```

**Pattern: Prompt construction**
- Lead with the task
- Provide all required input file paths
- State the output artifact name
- Include the quality gate (what "done" means)
- Keep prompts under 500 words — long prompts dilute attention

**Pattern: No worktrees for this workflow**
Never use `isolation: "worktree"` when spawning agents. All work in the main working directory.

---

### State Management Patterns

**Pattern: Write STATE.json at every phase transition, not at the end**

If an agent is interrupted mid-workflow, STATE.json must reflect where the workflow was last successfully completed. Write STATE.json immediately after each phase agent returns and before spawning the next.

```
# Correct order:
1. Spawn research agent
2. Research agent completes
3. Verify RESEARCH.md exists
4. Write STATE.json (current_phase: "architecture")
5. Spawn architecture agent
```

**Pattern: Artifact verification before STATE transition**

Never advance STATE.json to the next phase without verifying the expected artifact was created:
```
After research agent returns:
  Read docs/{issue_name}/RESEARCH.md
  If not found: set phase_status = "failed", alert user
  If found and valid: update STATE.json to next phase
```

**Pattern: Phase idempotency for resume**

Each phase agent should check if its output artifact already exists before doing work. If RESEARCH.md already exists and `--resume` was used, the orchestrator should skip that phase rather than re-running it.

---

### Security Patterns

**Pattern: Input sanitization at the command boundary**

The `/sdlc` command is the trust boundary. All user input must be validated here by Haiku before the orchestrator sees it:
- Issue name: enforce kebab-case pattern, no path traversal
- Description: strip HTML, escape shell metacharacters, enforce max length
- After this boundary, treat inputs as trusted

**Pattern: No secrets in artifacts**

All artifact files (RESEARCH.md, PLAN.md, IMPLEMENTATION.md, etc.) are committed to git. Agents must never write secrets, API keys, connection strings, or passwords to these files. The security reviewer runs secret detection on all new files.

**Pattern: Bash command scoping**

Allow only specific, known-safe bash commands in settings.json. Never `"allow": ["Bash"]` globally — this allows agents to run arbitrary shell commands including destructive operations. Scope with patterns: `"Bash(npm test*)"`, `"Bash(git diff*)"`.

**Pattern: No writes outside the project directory**

All file writes must go to `docs/{issue_name}/` (artifacts) or the project source tree (implementation). Never `/tmp`, never absolute paths outside the project. This prevents agents from accidentally modifying system files or leaking data to temporary directories.

---

### Model Selection Patterns

**Decision framework:**

| Complexity | Model | Examples |
|-----------|-------|---------|
| Parse and route | Haiku 4.5 | Command parsing, input validation |
| Sequential reasoning, code generation | Sonnet 4.6 | Research, implementation, reviews, docs |
| Complex trade-off analysis, adversarial thinking | Opus 4.6 | Architecture, orchestration, security review |

**Anti-pattern:** Using Opus for every agent. Opus costs ~5x more than Sonnet. Use it where complex reasoning is genuinely needed (architecture decisions, threat modeling) and Sonnet everywhere else.

**Anti-pattern:** Using Haiku for implementation. Haiku sacrifices too much code generation quality for the cost savings.

---

### Context Management Patterns

**Pattern: Front-load critical constraints**

The first ~2000 tokens of an agent prompt are most influential. Put the most important constraints (architectural decisions, scope boundaries, "do not" rules) at the top, not buried in a file the agent is told to read.

**Pattern: Artifact size discipline**

Artifacts that are read by multiple downstream agents (RESEARCH.md, PLAN.md) should be concise. A 5000-line RESEARCH.md consumes significant context in every downstream agent. The research agent should document minimum necessary context, not everything found.

**Pattern: Agent context budget estimate**

Each subagent gets ~200K tokens. Budget allocation:
- System prompt (agent .md file): ~2-5K tokens
- Orchestrator prompt (task description): ~1-2K tokens
- Prior artifacts (RESEARCH.md, PLAN.md, etc.): ~5-20K tokens
- Code files read during phase: ~10-50K tokens
- Working context (agent's own reasoning): ~20-50K tokens
- Output artifact writing: ~5-10K tokens

**Total budget per agent: easily fits in 200K.** If an agent reads more than ~100K tokens of code files, consider whether the research phase did its job of scoping the implementation correctly.

---

### Artifact Quality Patterns

**Pattern: Every artifact has a verdict**

For review artifacts (SECURITY.md, QA.md, SRE.md), the first section must be a clear, unambiguous verdict:
```markdown
## Verdict
**Status:** APPROVED
```
or
```markdown
## Verdict
**Status:** NEEDS_FIX
```

No hedging, no "partially approved", no "approved with conditions." The orchestrator reads this verdict programmatically.

**Pattern: Blocking vs non-blocking separation**

Every review artifact must separate issues into exactly two categories:
- **Blocking:** Must be fixed before APPROVED. The fix loop addresses these.
- **Non-Blocking:** Recommendations. The fix agent explicitly skips these.

This separation prevents the fix loop from over-engineering in response to suggestions.

**Pattern: Minimal STATUS.md updates**

STATUS.md is for human consumption only. Keep it brief — progress checkboxes, one key finding per phase, next step. It is never the source of truth for machine decisions.

---

## Implementation Guidance for Agents

### For Orchestrators

You are a coordinator, not an implementer. Your job is:
1. Read STATE.json → determine current phase
2. Spawn the appropriate subagent(s)
3. Wait for completion
4. Read the output artifact → verify it exists and is valid
5. Update STATE.json → advance to next phase
6. Notify the user of progress
7. Repeat until `current_phase = "complete"`

You must never implement phase logic inline. If you find yourself writing code, running tests, or doing security analysis, you are doing it wrong. Spawn a subagent.

### For Research Agents

Your job is minimum necessary context. Answer exactly three questions:
1. What files will this touch?
2. What patterns must be followed?
3. What are the risks?

Stop when you can answer these. Do not document the entire architecture. Do not trace full data flows. A RESEARCH.md over 300 lines is a sign you over-researched.

Use parallel tool calls for discovery — issue multiple Glob/Grep/Read calls in one response. Never research sequentially when parallel is possible.

### For Architecture Agents

An ADR is needed when a future developer would reasonably ask "why did they do it this way?"

If the approach is the obvious continuation of existing patterns, write: "No new architectural decisions required. Follow the {existing} pattern from {reference file}." This is a valid and often correct output.

Your most important output is the "Constraints for Planning" section — this is what the planning agent must respect. Make it specific and actionable.

### For Planning Agents

The plan is a contract between planning and implementation. It must be:
- **Specific enough** that the implementer knows what to build
- **Loose enough** that the implementer has room to apply better approaches

Do not specify implementation details (function signatures, variable names). Do specify: phases, scope boundaries, acceptance criteria, and per-phase validation commands.

Validation commands must be runnable commands, not aspirational statements. "Run tests" is not a validation command. `npm test -- --testPathPattern=auth` is.

### For Implementation Agents

You have a plan and you have a fresh context. Read the plan, count the phases, and implement all of them. The most common failure mode is stopping after Phase 1.

Never claim validation passed. Run the commands. Capture the output. Paste the output into IMPLEMENTATION.md. The output is the evidence.

When you deviate from the plan, document it in the "Deviations" section with the reason. The reviewers will read this.

### For Expert Reviewer Agents

You have one job: produce an unambiguous APPROVED or NEEDS_FIX verdict.

Classify every issue as blocking or non-blocking before writing the verdict. The verdict is NEEDS_FIX if and only if there is at least one blocking issue.

Focus on real, exploitable problems. A theoretical vulnerability with no realistic attack vector is non-blocking. A missing auth check on a new endpoint is blocking. Apply judgment proportionate to actual risk.

### For Fix Agents

You are a surgeon, not a renovator. Fix exactly the blocking issues listed in REVIEW.md. Do not fix non-blocking suggestions. Do not refactor unrelated code. Do not add new features.

After each fix, run the test suite. If a test fails that was passing before, you introduced a regression — fix it before updating REVIEW.md.

Maximum 3 iterations are tracked by the orchestrator. If an issue cannot be fixed in 3 iterations, it likely requires architectural reconsideration. The orchestrator will mark BLOCKED and escalate to the user.

### For Tech Writer Agents

Read IMPLEMENTATION.md and PLAN.md. Do not re-read all the code. These artifacts were written specifically so you don't have to.

The CHANGELOG should read like release notes — what can users do now that they couldn't before? Not: "Added GoogleOAuthStrategy class with verifyCallback method." Yes: "Added Google OAuth2 login."

Only update README sections where the feature adds new user-visible behavior (new commands, new config, new endpoints). Don't restructure unaffected sections.

---

## Quality Gates Summary

| Phase | Gate | Failure Action |
|-------|------|----------------|
| Research | RESEARCH.md exists and answers 3 questions | Re-spawn research agent |
| Architecture | ADR.md exists with "Constraints for Planning" | Re-spawn architect agent |
| Planning | PLAN.md has scope, phases, validation commands, acceptance criteria | Re-spawn planning agent |
| Implementation | IMPLEMENTATION.md has all phases complete with actual test output | Re-spawn implementation agent |
| Review (each expert) | SECURITY/QA/SRE.md has clear APPROVED/NEEDS_FIX verdict | Enter fix loop |
| Fix | All tests pass, blocking issues addressed | Re-run failing experts |
| Documentation | CHANGELOG.md updated | Re-spawn tech writer |
| Production | All 3 experts APPROVED, CHANGELOG updated, STATE.json = complete | BLOCKED |

---

## Workflow Anti-Patterns to Avoid

| Anti-Pattern | Problem | Correct Pattern |
|-------------|---------|----------------|
| Inline phase logic in orchestrator | Bloats orchestrator context, no isolation | Always use Agent tool for phases |
| Sequential expert review | 3x slower than parallel | Spawn all 3 experts in one response |
| Re-running all experts after a fix | Wastes tokens, approval drift risk | Track `failing_experts`, re-run only those |
| Claiming tests pass without output | Unverifiable assertion | Run tests, paste actual output |
| Reading STATUS.md for machine state | Fragile text parsing, stale data | Read STATE.json only |
| Writing secrets to artifacts | Git history leaks | Environment variables only |
| Using Bash for file reads | Bypasses permissions, injection risk | Use Read, Grep, Glob tools |
| Stopping after Phase 1 of implementation | Incomplete delivery | Explicit phase count check |
| ADR for every feature | Over-engineering | ADR only for non-obvious decisions |
| Runbook for every feature | Over-engineering | Runbook only for new operational surface |
| Global `"allow": ["Bash"]` in settings.json | Enables destructive commands | Scope with command patterns |

---

## Checklist for Implementing a New Workflow

Use this checklist when creating or extending an autonomous SDLC pipeline:

### Design
- [ ] Each phase is isolated in its own agent (no inline phase logic)
- [ ] Independent phases can run in parallel (identified and parallelized)
- [ ] STATE.json schema defined with all required fields
- [ ] Single artifact owner for each output file
- [ ] Human checkpoints identified for high-risk transitions

### Models
- [ ] Haiku assigned to parse-only tasks
- [ ] Sonnet assigned to implementation, generation, systematic review
- [ ] Opus assigned to architecture, complex reasoning, adversarial review

### Security
- [ ] Input validation at the command/entry boundary
- [ ] settings.json uses scoped Bash patterns (not global allow)
- [ ] No writes outside the project directory
- [ ] Secret detection in review phase

### State Management
- [ ] STATE.json written at every successful phase transition
- [ ] Resume logic reads STATE.json, not STATUS.md
- [ ] Artifact existence verified before phase transition
- [ ] Phase idempotency (resume skips completed phases)

### Fix Loop
- [ ] Maximum iteration count defined (3 recommended)
- [ ] `failing_experts` tracked and scoped
- [ ] Only failing experts re-run after fix
- [ ] BLOCKED state and escalation path defined

### Quality Gates
- [ ] Each phase has explicit completion criteria
- [ ] Evidence required (actual output, not claims)
- [ ] Blocking vs non-blocking issues separated in all reviews

---

*Document version: 2026.1 — Written as part of SDLC workflow expert review*
