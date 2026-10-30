---
model: sonnet
---

# /sdlc/continue — Resume Incomplete Workflow

Auto-detect and resume the next phase of an incomplete SDLC workflow.

## Instructions

### Step 1: Scan for Incomplete Workflows

List all directories under `.claude/planning/` that contain a `00_STATUS.md` or legacy `STATUS.md`.

For each directory found, read the STATUS.md file and check the `## Progress` section. A workflow is **incomplete** if:
- It has at least one unchecked `[ ]` progress item
- It does NOT contain the text `WORKFLOW COMPLETE`
- It is NOT marked as `BLOCKED`

Build a list of incomplete workflows with:
- **Issue name** (the directory name)
- **Last completed phase** (the last `[x]` item)
- **Next incomplete phase** (the first `[ ]` or `[~]` item)
- **Last updated timestamp** (from the `**Updated:**` field)

### Step 2: Select Workflow

**If zero incomplete workflows found:**
```
No incomplete SDLC workflows found in .claude/planning/.
Start a new one with: /discover [description]
```

**If exactly one incomplete workflow found — auto-select it:**
```
Found incomplete workflow: {issue-name}
Last completed: {phase}
Resuming from: {next-phase}
```

**If multiple incomplete workflows found — ask user to choose:**
```
Found {N} incomplete SDLC workflows:

1. {issue-name-1} — paused at {phase} (updated {date})
2. {issue-name-2} — paused at {phase} (updated {date})
3. {issue-name-3} — paused at {phase} (updated {date})

Which workflow would you like to continue? (enter number or issue name)
```

Wait for user selection before proceeding.

### Step 3: Determine Next Phase

Parse the Progress section of the selected `00_STATUS.md` (or `STATUS.md`). The phase-to-command mapping is:

| Progress Line Contains | Phase | Command to Invoke |
|---|---|---|
| `Discovery` | Discovery | `/discover` with existing description |
| `Research` | Research | `/research {issue-name}` |
| `Design` | Design | `/design-system {issue-name}` |
| `Planning` | Planning | `/plan {issue-name}` |
| `Design Review` | Goldfish Design Review | `/sdlc {issue-name} --design-review` |
| `Implementation` | Implementation | `/implement {issue-name}` |
| `CVE Gate` | Dependency CVE Gate | `/sdlc {issue-name} --cve` |
| `Review` | Review | `/review {issue-name}` |
| `Security` | Security | `/security {issue-name}` |
| `Deploy` | Deploy | `/deploy-plan {issue-name}` |
| `Observe` | Observe | `/observe {issue-name}` |
| `Retro` | Retro | `/retro {issue-name}` |

Find the **first** line with `[ ]` (not started) or `[~]` (in-progress). That determines the next phase.

**Special cases:**
- `[~]` (in-progress marker): Resume that phase, not the next one
- If Security is checked but you see no `07b_PENTEST_REPORT.md` and the project has a staging environment, mention that `/security/pentest {issue-name}` is available as an optional next step

### Step 4: Invoke the Phase Command

Announce what you are doing:
```
Continuing **{issue-name}** → {phase-name}...
```

Then execute the appropriate command as if the user had typed it directly.

### Backward Compatibility

Recognize both naming conventions for STATUS.md:
- New: `00_STATUS.md`
- Legacy: `STATUS.md`

Check for both when scanning directories. The phase detection logic works regardless of which naming convention the STATUS.md uses, since it only parses the `## Progress` checklist format.

### Quality Gates
- All directories under `.claude/planning/` were scanned
- Incomplete workflow detection is accurate (checked progress items)
- The correct next phase was identified
- The appropriate command was invoked with the correct issue name