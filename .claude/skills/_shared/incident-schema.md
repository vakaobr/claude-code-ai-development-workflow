# Incident Report Schema

All DFIR skills append to `.claude/planning/{case}/INCIDENT_REPORT.md`
using the format below. This is the incident-response analogue of
`finding-schema.md` (which the offensive hunters use). DFIR skills do NOT
write to `SECURITY_AUDIT.md` — incidents and assessments are separate
artifacts.

## File Structure

```markdown
# Incident Report: {case-id}

**Scope file:** .claude/security-scope.yaml → dfir_scope (version X.Y)
**Case ID:** IR-2026-0042
**Opened:** 2026-06-28 09:00 UTC
**Last updated:** 2026-06-28 14:32 UTC
**Lead responder:** {name}
**Classification:** {severity} — {functional/information/recoverability impact}
**Skills run:** memory-forensics-hunter, disk-triage-hunter, log-timeline-hunter

## Executive Summary

2-4 sentences: what happened, current status (active/contained/eradicated),
confirmed scope, and headline impact. Written for an incident commander.

## Evidence Register

| Item | Source host | Type | Acquired (UTC) | SHA-256 (acq) | SHA-256 (verify) | Custody ref |
|---|---|---|---|---|---|---|
| E01 | WKSTN-07 | RAM (20 GB) | 2026-06-28 08:10 | abc… | abc… ✓ | coc-log#3 |
| E02 | WKSTN-07 | Disk (E01.dd) | 2026-06-28 08:40 | def… | def… ✓ | coc-log#4 |

## Timeline (UTC)

| Time (UTC) | Host | Artifact / source | Event | ATT&CK | Confidence |
|---|---|---|---|---|---|
| 2026-06-25 13:02 | WKSTN-07 | Sysmon 1 | malicious.exe spawned from Outlook | T1566.001 | High |

## Findings

### IR-FINDING-001
[... entry, format below ...]

## IOCs

| Type | Value | Context | Source finding |
|---|---|---|---|
| sha256 | a1b2… | dropper binary | IR-FINDING-001 |
| ipv4 | 203.0.113.5 | C2 beacon dest | IR-FINDING-002 |
| domain | evil.example | C2 | IR-FINDING-002 |

## Skills Run Log

| Skill | Evidence | Started | Finished | Status | Findings |
|---|---|---|---|---|---|
| memory-forensics-hunter | E01 | 09:00 | 09:55 | complete | 3 |
```

## Per-Finding Entry Format

```markdown
### IR-FINDING-{NNN}

**Title:** {one-line, plain-language}
**Skill:** {skill-that-found-it}
**Phase:** Detection & Analysis
**Severity:** Critical | High | Medium | Low | Informational
**ATT&CK:** T{NNNN}[.{NNN}] {technique name}
**Status:** Confirmed | Suspected | Ruled out

**Host/Asset:** {hostname or evidence item}
**Evidence item:** {E0N from the register}
**Observed (UTC):** {timestamp or range}

---

**Summary**

{2-4 sentences in plain language. What the artifact shows and why it
indicates malicious / anomalous activity. No attacker bravado.}

**Evidence**

Command (reproducible, run against the verified copy):
\`\`\`bash
vol -f E01.mem windows.malfind | grep -i wkstn
\`\`\`

Output (excerpt, with offsets / artifact locations):
\`\`\`
Process injected: 4012 svch0st.exe  PAGE_EXECUTE_READWRITE  MZ header
\`\`\`

{Plain-English explanation of why this output demonstrates the activity.}

**Impact**

{What it means for the environment — data at risk, blast radius, whether
the threat is active. If low, say so.}

**Recommended response**

{Concrete containment/eradication/hardening, mapped to MITRE D3FEND where
possible. Framed for the operator who will action it under change control.
This skill does NOT perform these actions.}

**IOCs extracted**
- sha256: {hash}
- {ip/domain/path/registry key/mutex}

**References**
- {Internal: link to incident-response SKILL.md section}
- {External: ATT&CK technique page, tool docs}
```

## Rules for Skills Appending Findings

1. **Never alter the originals; analyze copies.** Verify the SHA-256
   against the Evidence Register before each session; if it mismatches,
   HALT and flag possible evidence tampering.
2. **Append-only.** Never rewrite prior findings or timeline rows. New
   corroboration is added, not edited in place.
3. **Monotonic IDs.** Read current file, find highest IR-FINDING-NNN,
   increment. Skills lock `.claude/planning/{case}/.incident.lock`
   before appending.
4. **One finding per distinct activity.** Don't bundle.
5. **Everything is reproducible.** Every finding carries the exact
   read-only command + artifact location so another responder can re-run
   it against the same image.
6. **Tag ATT&CK on every confirmed finding** and add its IOCs to the IOC
   table. Update the Skills Run Log and the timeline.
7. **A clean skill run still logs.** "No injected processes in E01 — N
   plugins run" is meaningful negative evidence.
