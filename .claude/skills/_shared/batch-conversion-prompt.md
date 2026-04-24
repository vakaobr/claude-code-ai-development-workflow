# Batch Conversion Prompt for Claude Code

## How to run this

1. Put these files in place in your repo:
   - `.claude/security-scope.yaml` (from foundation/)
   - `.claude/skills/_shared/finding-schema.md` (from foundation/)
   - `.claude/skills/_shared/tool-profiles.md` (from foundation/)
   - `.claude/skills/_shared/name-mapping.md` (from foundation/)
   - Append the CLAUDE.md snippet to your existing `CLAUDE.md`
   - Keep your `pentest-agent-development/notebooklm-notes/` directory
     where it is.

2. Run this from your repo root:
   ```
   claude
   ```

3. Paste the prompt below as your first message.

4. Claude Code will ask clarifying questions up front, then iterate
   through all 41 notes. Expect ~20-40 minutes. Review as it goes.

---

## THE PROMPT

You are converting 41 security testing methodology notes into Claude
Code skills for a defensive security testing workflow. The notes are in
`pentest-agent-development/notebooklm-notes/`. Their filenames are in
Portuguese but their contents are in English. They were produced by
NotebookLM grounded in 13 bug bounty / web app security textbooks.

You are extending the repo structure from
vakaobr/claude-code-ai-development-workflow, which uses folder-based
skills under `.claude/skills/{skill-name}/SKILL.md`.

## Inputs You Must Read First

Before generating anything, read these files in order and confirm you
understand them:

1. `.claude/skills/_shared/name-mapping.md` — the authoritative mapping
   from Portuguese filenames to English kebab-case skill names, with
   model and tools-profile assignments.
2. `.claude/skills/_shared/tool-profiles.md` — the allowed-tools
   profiles. Every skill references one of these by name.
3. `.claude/skills/_shared/finding-schema.md` — the canonical schema
   for SECURITY_AUDIT.md entries. Every skill's Output Format section
   must produce findings in this schema.
4. `.claude/security-scope.yaml` — the authorization declaration.
   Every skill reads this before any outbound activity.
5. `CLAUDE.md` section "Security Testing Scope and Authorization" —
   the rules of engagement every skill inherits.

After reading these, summarize back to me in 5 bullets what you
understood. Do not start converting until I confirm.

## Batch Workflow

For each of the 41 notes in `pentest-agent-development/notebooklm-notes/`:

1. Look up the note's skill name, category, model, and tools profile
   in the mapping table.

2. Handle the three SSTI notes specially — they're the same topic. Read
   all three, pick the most comprehensive as the base, fold useful
   material from the other two into the `references/` folder. Produce
   one skill: `ssti-hunter`.

3. Read the source note in full.

4. Produce the output at `.claude/skills/{skill-name}/SKILL.md` using
   the template below.

5. Extract supplementary material into `references/` subdirectory files
   when a note contains: a long payload list (→ `payloads.md`), a tool
   cookbook (→ `tooling.md`), detection regex patterns (→ `signatures.md`),
   or a remediation code snippet library (→ `remediation.md`).

6. After completing each skill, print a one-line status:
   `[NN/41] {skill-name}: done ({wordcount} words, {refs} ref files)`

7. Every 5 skills, stop and show me one completed SKILL.md for review.
   Wait for my go-ahead before continuing.

## SKILL.md Template

Produce each SKILL.md in exactly this structure. Deviations break the
orchestrator.

```markdown
---
name: {skill-name}
description: "{ONE SENTENCE of what it does}. Use when {TRIGGERING CONDITIONS — 2-3 specific scenarios}. {CAPABILITIES in 1 sentence}. Defensive testing only, against assets listed in .claude/security-scope.yaml."
model: {sonnet|opus from mapping}
allowed-tools: {paste the exact allowed-tools block from the matching profile in tool-profiles.md}
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: {category from mapping — injection, access-control, etc.}
  authorization_required: true
  tier: {T1|T2|T3|T4 from mapping}
  source_methodology: {original Portuguese filename}
  service_affecting: {true|false — true for rate-limit, fuzzing, brute-force classes}
  composed_from: []  # populated by merge skills, empty here
---

# {Skill Title in English, human-readable}

## Goal

{One paragraph, defensive framing. What this skill helps the team
harden, not what it helps an attacker break. Mention which OWASP
reference it implements: WSTG-XXX-NN, API{N}:2023, or ASVS Vnn.}

## When to Use

- {Specific trigger 1 — an observable condition in the target}
- {Specific trigger 2}
- {Specific trigger 3}
- {Specific trigger 4}
- User invokes via `/{skill-name}` or the orchestrator selects this
  skill based on attack surface inventory.

## When NOT to Use

- {Adjacent class this skill should defer to — e.g., "Use bola-bfla-hunter
  for API-level object authorization, this skill is for web-app IDOR"}
- {Target condition that rules out this test}
- Any asset not listed in `.claude/security-scope.yaml`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or
   doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND the
   target's `testing_level` is `active` (or `passive` if this skill
   is passive-only).
3. If this skill's frontmatter has `service_affecting: true`, AND the
   asset's `service_affecting` field is `denied`, halt and request
   explicit user approval with a clear prompt.
4. If the target is ambiguous (not explicitly listed), write the
   ambiguity to `.claude/planning/{issue}/SCOPE_QUESTIONS.md` and halt
   on that target only. Continue other in-scope work.
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log before
   producing any probes.

## Inputs

The skill expects the caller to provide:
- `{issue}`: the planning folder name (e.g., `security-audit-q2`)
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific endpoints/parameters to focus on
- {any skill-specific inputs — e.g., for idor-hunter: authenticated
  session tokens for two different users}

## Methodology

{CONVERT THE SOURCE NOTE'S METHODOLOGY SECTION HERE. Preserve every
test step. Rewrite as direct instructions to Claude. Each step should
name its source book citation inline, like this:}

### Phase 1: {Name}

1. **{Test name}** [WAHH Ch. 12]

   Do: {specific action}

   Vulnerable response: {what confirms the flaw}

   Not-vulnerable response: {what rules it out}

   Record: If vulnerable, append FINDING-NNN to SECURITY_AUDIT.md
   following the schema in `.claude/skills/_shared/finding-schema.md`.

2. **{Next test}** [OWASP WSTG-XXX-NN]

   ...

### Phase 2: {Name}

...

{Keep going until all source material is captured. Minimum 8 distinct
test steps. If the source has fewer than 8, note "source methodology
covers limited techniques for this class" and stop there — do not
invent additional steps.}

## Payload Library

{If the source note has payloads, summarize their CATEGORIES here and
put the full list in `references/payloads.md`. Do not paste long
payload dumps into SKILL.md directly.}

- **Category 1**: {1-line description} — see `references/payloads.md`
- **Category 2**: {...}

## Output Format

This skill produces findings that append to
`.claude/planning/{issue}/SECURITY_AUDIT.md` using the schema in
`.claude/skills/_shared/finding-schema.md`.

Specifically for this skill, each finding:
- Uses CWE: CWE-{default for this class}
- Uses OWASP reference: {WSTG or API Top 10 default}
- Includes evidence: {what this skill captures as PoC — request/response
  pair, DOM snippet, HTTP response code, etc.}
- Remediation framing: {who the fix is for — backend dev, frontend dev,
  DBA, infra, etc.}

The skill also updates:
- `.claude/planning/{issue}/STATUS.md` — checkbox for this skill under
  Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log — start
  and finish rows

## Quality Check (Self-Review)

Before declaring the skill run complete, verify:

- [ ] Every finding has the required schema fields populated
- [ ] No finding cites a source not in the loaded methodology
- [ ] No finding is a duplicate of an earlier FINDING-NNN for the same
      endpoint + technique combination
- [ ] Remediation text is concrete (code or config) — not generic
      advice like "use proper validation"
- [ ] Skills Run Log row is updated from `running` to `complete` or
      `halted:{reason}`
- [ ] No out-of-scope assets were probed (grep the SECURITY_AUDIT.md
      skill's logged requests against the scope file)

## Common Issues

{Extract false-positive patterns from the source note and list 3-6
here. Format: "**{Pattern}**: {why it looks vulnerable but isn't} →
{how to confirm}".}

## References

- `references/payloads.md` — {what's in it}
- `references/tooling.md` — {what's in it, only if note had tool
  commands}
- `references/signatures.md` — {only if note had detection regex}
- `references/remediation.md` — {only if note had fix code library}

External:
- {OWASP WSTG section URL}
- {CWE page URL}
- {Primary book reference from the note's Source Index}

## Source Methodology

Converted from: `pentest-agent-development/notebooklm-notes/{original-filename}`

Grounded in:
- {book 1 from the note's Source Index}
- {book 2}
- {...}

Conversion date: {today}
Conversion prompt version: 1.0
```

## Hard Rules

These rules are non-negotiable:

1. **Never invent methodology.** If the source note doesn't cover
   something, don't add it. If you think a well-known technique is
   missing, add it to `references/gaps.md` for a human to review —
   never into the methodology itself.

2. **Never broaden allowed-tools.** The tools profile in the mapping
   is the ceiling. A skill may narrow it; it may not widen it.

3. **Defensive framing only.** Every piece of attacker-voice copy gets
   rewritten. "Attacker can steal..." becomes "An unauthenticated
   request can access..." and every finding has a remediation block.

4. **Authorization check is mandatory.** No skill ships without the
   Authorization Check section, verbatim from the template (adapt
   only the asset-type specifics).

5. **references/ files are optional.** If the source note has no
   payloads, don't create an empty `references/payloads.md`. Create
   only what the note supports.

6. **No Portuguese in the output.** The source notes are in English
   despite Portuguese filenames, so this should be natural — but
   watch for any Portuguese section headers that leak through.

7. **Update STATUS.md format compatibly.** The existing repo uses
   Phase 7: Security as a single checkbox. Your skills add sub-items
   under it, like this:
   ```
   - [x] Phase 7: Security
     - [x] idor-hunter (3 findings)
     - [x] sqli-hunter (0 findings)
     - [~] xss-hunter (running)
   ```

## Output Location

- Main skills: `.claude/skills/{skill-name}/SKILL.md`
- References: `.claude/skills/{skill-name}/references/*.md`
- Shared: `.claude/skills/_shared/` (already populated, don't touch)
- Log: Append conversion results to
  `.claude/planning/skill-conversion/STATUS.md` as you go

## Start

Read the five inputs listed under "Inputs You Must Read First".
Summarize them back to me in 5 bullets. Wait for my confirmation
before converting any skills.
