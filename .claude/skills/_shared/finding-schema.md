# Security Finding Schema

All security skills append findings to
`.claude/planning/{issue}/SECURITY_AUDIT.md` using the format below.
This is the canonical schema. Skills that deviate from it break the
orchestrator's aggregation logic.

## File Structure

```markdown
# Security Audit: {issue-name}

**Scope file:** .claude/security-scope.yaml (version X.Y)
**Started:** 2026-04-23 09:00 UTC
**Last updated:** 2026-04-23 14:32 UTC
**Skills run:** idor-hunter, sqli-hunter, xss-hunter, auth-flaw-hunter

## Executive Summary

- Critical: 0
- High: 2
- Medium: 5
- Low: 8
- Informational: 12

## Findings

### FINDING-001

[... finding entry, format below ...]

### FINDING-002

[... next finding ...]

## Skills Run Log

| Skill | Started | Finished | Status | Findings |
|---|---|---|---|---|
| idor-hunter | 09:00 | 09:47 | complete | 3 |
| sqli-hunter | 09:48 | 10:35 | complete | 0 |
| xss-hunter | 10:36 | 11:20 | complete | 4 |
```

## Per-Finding Entry Format

Every finding is a single Markdown block in this exact shape. Skills
append these; they never rewrite prior findings.

```markdown
### FINDING-{NNN}

**Title:** {one-line, developer-readable}
**Skill:** {skill-name-that-found-it}
**Severity:** Critical | High | Medium | Low | Informational
**CVSS v3.1:** {vector string, if applicable}
**CWE:** CWE-{number} {CWE name}
**OWASP:** {ASVS ref, API Top 10 ref, or WSTG ref}
**Status:** Confirmed | Suspected | False Positive | Rejected

**Asset:** {from security-scope.yaml — exact name}
**Endpoint:** {URL or resource identifier}
**Discovered:** 2026-04-23 09:22 UTC

---

**Summary**

{2-4 sentences explaining the issue in developer terms. No jargon
without a parenthetical definition. No attacker voice.}

**Evidence**

Request:
\`\`\`http
GET /api/users/42/profile HTTP/1.1
Host: api.internal.example.com
Cookie: session=user-99-session
\`\`\`

Response:
\`\`\`http
HTTP/1.1 200 OK
{
  "user_id": 42,
  "email": "other.user@example.com",
  ...
}
\`\`\`

{Plain-English explanation of why this evidence demonstrates the flaw.}

**Impact**

{Business impact for our environment, not generic. If low, say so.}

**Remediation**

{Concrete fix, ideally with code. Framed for the owning team.}

\`\`\`python
# Before
user = User.objects.get(id=user_id_from_url)

# After
user = User.objects.get(id=user_id_from_url)
if user.id != request.user.id and not request.user.is_admin:
    raise PermissionDenied
\`\`\`

**References**
- {Internal: link to the relevant SKILL.md section}
- {External: WSTG, OWASP, CWE page}

**Source methodology**
- {Which loaded book section the test came from,
   e.g., "WAHH Ch. 8 - Attacking Access Controls"}
```

## Rules for Skills Appending Findings

1. **Never rewrite prior findings.** Append-only. If a new run of the same
   skill confirms an already-reported finding, add a "Re-confirmed"
   timestamp to that entry via append, don't edit.

2. **Use monotonic finding IDs.** Read the current file, find the highest
   FINDING-NNN, increment. Race conditions across parallel skills are the
   orchestrator's problem, not the skill's — skills acquire a lock via
   `.claude/planning/{issue}/.audit.lock` before appending.

3. **One finding per issue.** Do not bundle "five XSS findings" into one
   entry. Each distinct vulnerable endpoint gets its own FINDING-NNN.

4. **Update the Skills Run Log.** Before starting, append a row with
   status: running. On completion, update that row.

5. **Update the Executive Summary counts** after appending. This is the
   only existing content skills are permitted to modify.

6. **If no findings, still log the run.** An empty skill run is valuable
   data — it means that vulnerability class is clean for this scope.
