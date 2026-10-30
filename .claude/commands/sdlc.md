---
name: sdlc
description: Execute complete SDLC: Research → Plan → Goldfish Design Review → Implement → CVE Gate → Review. Autonomous, single command for full feature development.
model: sonnet
---

You are the UX interface for the SDLC Orchestrator Agent.

## Purpose

Parse user input and invoke the SDLC Orchestrator Agent. **Contain NO workflow logic.**

## Command Syntax

```
/sdlc <issue-name> [description] [--design <path>] [--no-design-review] [--resume | --plan | --design-review | --implement | --cve | --review]
```

## Arguments

**Positional:**
- `issue-name` (required): Kebab-case identifier, 1-50 chars
- `description` (optional): What to build, max 1000 chars

**Options:**
- `--design <path>`: Start from an approved design document inside the project, for example one written with `/egm-brainstorm`, `/egm-draft` and `/egm-review`. Architecture and Planning work within it instead of re-deciding it.
- `--no-design-review`: Skip the Goldfish design review (Phase 3b). The skip is recorded. Small, low-risk fixes skip it automatically.

**Entry points:**
- `--resume`: Continue from where STATUS.md left off
- `--plan`: Start from Planning phase (requires RESEARCH.md)
- `--design-review`: Run only the Goldfish design review on the existing plan (requires RESEARCH.md, ADR.md and PLAN.md)
- `--implement`: Start from Implementation (requires PLAN.md; runs the design review first unless it was approved or skipped)
- `--cve`: Start from the Dependency CVE Gate (requires IMPLEMENTATION.md)
- `--review`: Start from Review (requires IMPLEMENTATION.md; runs the CVE Gate first if CVE_REMEDIATION.md is missing)

## Input Validation

### Issue Name Rules

- Must be kebab-case (lowercase-with-hyphens)
- 1-50 characters
- Cannot start/end with hyphen
- No path traversal (`..`, `/`, `\`)

**Examples:**
- ✅ `add-oauth-auth`, `fix-memory-leak`, `refactor-api`
- ❌ `AddOAuthAuth` (not kebab-case)
- ❌ `../etc/passwd` (path traversal)

### Description Rules

- Max 1000 characters
- HTML stripped
- Shell metacharacters escaped

## Agent Invocation

```
INVOKE AGENT: .claude/agents/sdlc-orchestrator.md

PARAMETERS:
- issue_name: <parsed issue-name>
- description: <parsed description>
- entry_point: <default|resume|plan|design_review|implement|cve|review>
- design_doc: <path from --design, or null>
- skip_design_review: <true for --no-design-review, else false>
```

`--design` paths follow the same rules as issue names for safety: relative to the project, no `..`, no absolute paths.

## Goldfish design review

Between Planning and Implementation, fresh-context reviewers from the vendored Elephant-Goldfish Model (`.claude/vendor/egm` in a project install, `~/.claude/vendor/egm` in a user install; pinned, see its `NOTICE.md`) review the design and plan without the conversation that produced them. Clear findings are fixed in ADR.md and PLAN.md, wrong ones are contested with evidence, and real trade-offs come to you at the plan confirmation. The review runs at most 2 rounds.

The EGM skills are also available on their own, outside `/sdlc`: `/egm-brainstorm`, `/egm-draft`, `/egm-review`, `/egm-review-loop`, `/egm-resolve`, `/egm-bootstrap`. Upgrade the vendored copy with `python3 ~/.claude/scripts/sync-egm.py --ref <reviewed commit>` (for a project install: `python3 .claude/scripts/sync-egm.py --root .claude --ref <reviewed commit>`).

## Examples

```bash
# Full workflow
/sdlc add-oauth-auth Implement OAuth2 with Google

# Resume after interruption
/sdlc add-oauth-auth --resume

# Start from specific phase
/sdlc add-oauth-auth --plan

# Build from an approved EGM design document
/sdlc add-webhook-delivery --design docs/designs/webhook_delivery.md

# Small fix, no design review
/sdlc fix-null-timezone Handle a missing timezone in the report job --no-design-review

# Re-run only the design review after editing the plan
/sdlc add-oauth-auth --design-review
```

## Error Responses

**Invalid Issue Name:**
```
❌ Invalid issue name: "AddOAuthAuth"

Must be kebab-case: add-oauth-auth
```

**Missing Required Artifact:**
```
❌ Cannot start from Planning: RESEARCH.md not found

Run: /sdlc add-oauth-auth
```

## After Agent Completion

Present:
1. Final status (complete/blocked)
2. Artifacts in `docs/{issue-name}/`
3. Suggested commit message (if complete)
4. Next steps (if blocked)
