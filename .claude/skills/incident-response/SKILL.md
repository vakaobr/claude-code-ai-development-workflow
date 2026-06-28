---
name: incident-response
description: >
  Reference skill for digital forensics and incident response (DFIR).
  Provides the NIST SP 800-61 incident lifecycle (Preparation,
  Detection & Analysis, Containment/Eradication/Recovery, Post-Incident),
  the SANS PICERL phases, evidence-handling and chain-of-custody rigor
  (NIST SP 800-86), a triage decision tree, an IOC / MITRE ATT&CK
  mapping model, and tool maps for memory / disk / log / network
  forensics. Load this skill before or during any incident to ground the
  executable memory-forensics-hunter, disk-triage-hunter, and
  log-timeline-hunter skills. Knowledge only - no execution; the
  responder runs the tools against evidence copies.
model: opus
metadata:
  version: 1.0.0
  category: security
  subcategory: dfir-incident-response
  grounds_skills: [memory-forensics-hunter, disk-triage-hunter, log-timeline-hunter]
  sources: ["NIST SP 800-61r2", "NIST SP 800-86", "SANS PICERL", "MITRE ATT&CK", "MITRE D3FEND"]
---

# Incident Response & Digital Forensics Reference

> **Knowledge skill.** No `allowed-tools`, runs no commands. It is the
> methodology layer that grounds the executable `memory-forensics-hunter`,
> `disk-triage-hunter`, and `log-timeline-hunter` skills. Those are gated
> by `.claude/security-scope.yaml` (`dfir_scope.incident_response:
> approved`). Loading this reference authorizes nothing.

> **Evidence integrity is the prime directive.** Every action below
> assumes you work on a **verified copy** of evidence (write-blocked
> acquisition, hash-verified image), never the original. Record a
> chain of custody for every artifact. If you cannot preserve
> integrity, stop and escalate to the responder lead.

---

## 1. The Incident Lifecycle (NIST SP 800-61 / SANS PICERL)

NIST's four phases map onto SANS's six-step PICERL. Use whichever
vocabulary the client uses; the work is the same.

| NIST SP 800-61 | SANS PICERL | Goal |
|---|---|---|
| Preparation | **P**reparation | Tooling, baselines, IR plan, authorization in place BEFORE an incident |
| Detection & Analysis | **I**dentification | Confirm an incident is real, scope it, classify severity |
| Containment, Eradication & Recovery | **C**ontainment / **E**radication / **R**ecovery | Stop spread, remove the threat, restore to known-good |
| Post-Incident Activity | **L**essons learned | Root cause, timeline, report, control improvements |

The hunters in this extension live in **Detection & Analysis** - they examine acquired evidence to confirm, scope, and attribute. They
do NOT contain or eradicate (those are operator-driven, change-
controlled actions on live systems).

### Severity / triage decision tree
1. **Is it a real incident or a false positive?** Correlate the alert
   against baseline. Benign-explained → close with note.
2. **What is the blast radius?** Single host vs lateral movement vs
   domain-wide. Drives whether you escalate to a full IR.
3. **Is data confidentiality/integrity/availability impacted?** PII /
   regulated data exfil raises severity and triggers legal/notification.
4. **Is the threat still active?** Live C2 / ongoing encryption → fast-
   track containment in parallel with analysis.
5. **Classify** (e.g., NIST functional + information + recoverability
   impact) and assign severity. Record the rationale.

---

## 2. Evidence Handling & Chain of Custody (NIST SP 800-86)

Order of volatility - collect most-volatile first:
1. CPU registers / cache, running process & memory (RAM)
2. Network state (connections, ARP, routing), running services
3. Disk (filesystem, slack, unallocated)
4. Remote/logging hosts, monitoring data
5. Physical config, archival media

Rules:
- **Acquire before you analyze.** Image RAM and disk with write-blocking;
  compute and record cryptographic hashes (SHA-256) at acquisition and
  re-verify before each analysis session.
- **Work on copies only.** Originals go to secure storage
  (`dfir_scope.evidence_store_path`), referenced by a `case_id`.
- **Chain of custody log**: who/what/when/where for every transfer and
  access. Append-only. (`dfir_scope.chain_of_custody_log`.)
- **Document commands run** (the hunters log every command + output hash)
  so analysis is reproducible and defensible.
- **Time discipline**: record acquisition timezone; normalize all
  timelines to UTC; note clock skew per source.

---

## 3. Artifact Map (where the evidence lives)

### Memory (RAM image) - see `memory-forensics-hunter`
Running/hidden processes, injected code, network connections, loaded
DLLs/drivers, command lines, cached credentials, rootkit traces,
unpacked malware. Tool: **Volatility 3**.

### Disk / filesystem - see `disk-triage-hunter`
- **Windows**: `$MFT`, `$UsnJrnl`, registry hives (SYSTEM/SOFTWARE/
  NTUSER), Amcache/Shimcache, Prefetch, SRUM, scheduled tasks, services,
  WMI persistence, `$Recycle.Bin`, browser artifacts, LNK/jumplists.
- **Linux/macOS**: `/var/log`, bash/zsh history, cron/systemd units,
  `/etc/passwd`+shadow, SSH `authorized_keys`, `.bash_profile`, launch
  agents/daemons (macOS), `/tmp` droppers.
  Tools: **Sleuth Kit** (`fls`/`icat`/`mmls`), **plaso** (`log2timeline`/
  `psort`), registry parsers, **YARA**.

### Logs / event records - see `log-timeline-hunter`
- **Windows Event Logs** (Security/System/Sysmon): 4624/4625 (logon),
  4672 (priv), 4688 (proc create), 7045 (service install), 4720 (user
  create), Sysmon 1/3/7/11/13.
- **Linux**: auth.log/secure, syslog, audit.
- **Network**: firewall/proxy/DNS logs, NetFlow, PCAP.
  Tools: **Chainsaw**, **Hayabusa** (Sigma over EVTX), **plaso**,
  **tshark/Zeek** for PCAP.

### Cloud
CloudTrail / GuardDuty / Azure Activity / GCP Audit logs, IAM changes,
unusual API calls. (Reuse `aws-iam-hunter` read-only verbs for AWS-side
context; full cloud-IR tooling is a future extension.)

---

## 4. Detection & Attribution Model

- **IOCs**: hashes, IPs, domains, mutexes, file paths, registry keys,
  user-agents. Extract them as you go; they pivot the investigation and
  seed blocking.
- **Map to MITRE ATT&CK**: tag each confirmed activity with a technique
  ID (e.g., T1055 Process Injection, T1003 Credential Dumping, T1053
  Scheduled Task, T1021 Lateral Movement). ATT&CK gives a shared
  vocabulary and exposes gaps ("we saw initial access + execution but no
  persistence yet - keep looking").
- **Map response to MITRE D3FEND** for the recommendation side.
- **Build the timeline**: a single super-timeline (plaso) correlating
  memory, disk, and logs in UTC is the backbone of the final report.

---

## 5. Reporting

Findings go to `.claude/planning/{case}/INCIDENT_REPORT.md` using
`.claude/skills/_shared/incident-schema.md`. The report answers:
what happened, when (timeline), how (initial access → impact, mapped to
ATT&CK), what was affected (scope), what was taken (impact), IOCs for
blocking, and prioritized remediation / hardening (D3FEND-mapped).

---

## 6. What this extension does NOT do

- **Containment / eradication on live systems** (isolating hosts,
  killing processes, resetting credentials) - change-controlled operator
  actions, not automated.
- **Live-response on production** without `dfir_scope.allow_live_response:
  approved` - default is offline analysis of acquired evidence.
- **Malware reverse engineering** beyond triage (strings/YARA/behavioral)
 - deep RE is a separate discipline.
- **Legal/regulatory notification decisions** - surfaced to the IR lead,
  never auto-actioned.

---

## References

- NIST SP 800-61r2 - Computer Security Incident Handling Guide
- NIST SP 800-86 - Guide to Integrating Forensic Techniques into IR
- SANS PICERL / DFIR cheat-sheets and posters
- MITRE ATT&CK: https://attack.mitre.org/ - MITRE D3FEND: https://d3fend.mitre.org/
- Volatility 3: https://volatility3.readthedocs.io/
- The Sleuth Kit / Autopsy: https://www.sleuthkit.org/
- plaso / log2timeline: https://plaso.readthedocs.io/
- Chainsaw: https://github.com/WithSecureLabs/chainsaw - Hayabusa: https://github.com/Yamato-Security/hayabusa

Pairs with `offensive-security` (the attacker's-eye reference) - knowing
how intrusions are built makes their artifacts easier to find.
