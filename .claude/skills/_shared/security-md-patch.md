# Integration with Existing /security Command

The repo already has `.claude/commands/security.md` as Phase 7 of the
SDLC workflow. Your 40 new skills should not replace it — they should
be what it invokes when the scope warrants deeper testing.

## The change

Keep the existing `/security` command as the entry point. Edit it to
delegate based on scope complexity:

- **Small scope, low risk** → existing checklist behavior (unchanged)
- **Large scope or high risk** → delegate to `security-orchestrator`
  agent

## Patch to apply to `.claude/commands/security.md`

Add this decision block near the top of the command body, after the
existing authorization check but before the checklist execution:

```markdown
## Delegation Decision

Before running the checklist, determine whether to delegate to the
security-orchestrator agent.

Delegate to `security-orchestrator` if ANY of these are true:

1. `.claude/security-scope.yaml` declares more than 3 assets with
   `testing_level: active`
2. `STATUS.md` for this issue has `Risk: High`
3. The user's request explicitly asks for "full", "deep", "comprehensive",
   or "orchestrated" assessment
4. The issue's DISCOVERY.md flags any of:
   - Authentication/authorization changes
   - New API endpoints
   - Handling of user-uploaded content
   - Changes to tenant-isolation logic
   - Integration with new third-party services
   - Cryptographic key or secret handling

If delegating:
- Invoke `@security-orchestrator {issue}`
- Do NOT run the checklist in parallel; the orchestrator supersedes it
- Wait for the orchestrator's SECURITY_REPORT.md before marking Phase 7
  complete in STATUS.md

Otherwise, proceed with the original OWASP/STRIDE checklist below.
```

## Also update the Phase 7 checkbox in STATUS.md

The existing repo renders Phase 7 as a single checkbox:
```
- [ ] Security
```

With the orchestrator running, it should render as:
```
- [~] Security (orchestrated)
  - [x] Phase 1: Reconnaissance (3 skills)
  - [x] Phase 2: Authentication (4 skills, 2 findings)
  - [~] Phase 3: Access Control (in progress)
  - [ ] Phase 4: Injection
  - [ ] Phase 5: Client-side
  - [ ] Phase 6: API
  - [ ] Phase 7: Infrastructure
  - [ ] Phase 8: Cross-cutting
  - [ ] Phase 9: Report
```

This requires a small edit to the orchestrator's progress reporting —
already described in its spec.

## CLAUDE.md Learnings section

After the orchestrator runs for the first time on a real issue, the
`/retro` command (Phase 10) should append to CLAUDE.md's Learnings
section. Add this guidance to the retro command:

```markdown
When Phase 7 used the security-orchestrator:
- Summarize which skills found the most findings (signal for where
  the team's guardrails are weakest)
- Summarize which skills consistently find nothing (signal for
  retiring or consolidating them)
- Note any scope questions that came up — they likely indicate
  scope file staleness
- Capture any false-positive patterns as learnings, so future runs
  of the same skill can reference them
```
