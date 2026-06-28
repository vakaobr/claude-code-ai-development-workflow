---
name: log-timeline-hunter
description: "Analyzes acquired logs during an authorized incident - Windows Event Logs (EVTX, incl. Sysmon) via Chainsaw/Hayabusa with Sigma rules, Linux auth/syslog/audit, and network logs/PCAP via tshark/Zeek - to reconstruct the attack timeline and detect logon anomalies, credential attacks, lateral movement, service/task install, and C2 beaconing. Correlates into a single UTC timeline and maps events to MITRE ATT&CK (T1110, T1021, T1059, T1543, T1071). Use when log/EVTX/PCAP evidence exists in Detection & Analysis. Requires .claude/security-scope.yaml dfir_scope.incident_response: approved and evidence from dfir_scope.evidence_store_path. Read-only on evidence copies; no containment. Grounded in incident-response."
model: sonnet
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  Bash(chainsaw:*), Bash(hayabusa:*), Bash(evtx_dump:*),
  Bash(log2timeline.py:*), Bash(psort.py:*), Bash(pinfo.py:*),
  Bash(tshark:*), Bash(zeek:*), Bash(capinfos:*),
  Bash(yara:*), Bash(strings:*), Bash(jq:*),
  Bash(sha256sum:*), Bash(md5sum:*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: dfir-logs
  authorization_required: true
  tier: T1
  profile: dfir-readonly
  source_methodology: "incident-response (NIST SP 800-61/86, Sigma, Chainsaw/Hayabusa docs)"
  service_affecting: false
  dfir: true
  composed_from: [incident-response]
---

# Log & Timeline Hunter

## Goal

Turn acquired log evidence into an attack narrative: who logged in from
where and when, what executed, how the attacker moved laterally, what
persisted, and where C2 went. Logs provide the temporal backbone of an
incident and frequently the only record on hosts that weren't imaged.
The skill runs Sigma-based detection (Chainsaw/Hayabusa) over Windows
Event Logs, parses Linux/network logs, and folds everything into one
UTC timeline with ATT&CK tags. Read-only on evidence copies; no
containment.

## When to Use

- An incident is authorized and log evidence exists: EVTX exports,
  Sysmon logs, Linux `auth.log`/`audit.log`, firewall/proxy/DNS logs, or
  PCAP.
- During Detection & Analysis to build/extend the incident timeline and
  to scope lateral movement across hosts.
- To corroborate memory/disk findings with temporal log evidence (e.g.
  confirm when an injected process first started, or trace a logon chain).

## When NOT to Use

- Live log collection / SIEM querying on production infrastructure
  without `dfir_scope.allow_live_response: approved` - this skill works on
  acquired log copies.
- Memory or disk artifacts - use the sibling skills.
- Real-time alerting / detection-engineering (writing new Sigma content
  for the SOC) - that is a separate workflow.

## Authorization Check (MANDATORY FIRST STEP)

1. Read `.claude/security-scope.yaml`. If missing/placeholder, halt.
2. Confirm `dfir_scope.incident_response: approved` and a `case_id`.
3. Resolve log evidence from `dfir_scope.evidence_store_path`; compute
   `sha256sum` of each artifact and compare to the Evidence Register.
   **Mismatch → HALT.**
4. Confirm analysis is on COPIES of the logs.
5. Append a `running` row to the case Skills Run Log.

## Inputs

- `{case}`: case folder name
- `{logs}`: path(s) to acquired logs (EVTX dir, syslog, PCAP)
- `{hosts}`: hosts the logs come from
- `{window}`: suspected incident time window (UTC) for slicing
- `{iocs}`: optional - IOCs from prior phases to pivot on

## Methodology

> Capture each command + output excerpt as evidence. Normalize all times
> to UTC; record source timezone and clock skew.

### Phase 1: Windows Event Logs (Sigma detection)
1. **Broad Sigma sweep.**
   Do: `chainsaw hunt {logs} -s <sigma> --mapping <map> -o chainsaw.json`
   and/or `hayabusa csv-timeline -d {logs} -o hayabusa.csv`. Triage the
   high/critical hits first.
2. **Authentication analysis.**
   Do: filter for 4624/4625/4634/4647/4648 (logon/logoff/explicit-creds)
   and 4672 (special privileges). Flag: brute force (many 4625 then a
   4624 - T1110), pass-the-hash (logon type 3, NTLM, anomalous source),
   anomalous logon hours/sources.
3. **Execution & persistence events.**
   Do: 4688 / Sysmon 1 (process create - decode command lines), 7045
   (service install - T1543.003), 4698 (scheduled task - T1053.005),
   4720/4732 (account create / group add - T1136/T1098), Sysmon 7
   (image load), 11/13 (file/registry).

### Phase 2: Lateral Movement
4. **Cross-host logon chains.**
   Do: correlate 4624 type 3/10 + 4648 across hosts to trace the
   movement path; pair with Sysmon 3 (network connect) and service/task
   creation on the destination (T1021 / T1570). Produce a movement graph
   in the timeline.

### Phase 3: Linux / Unix Logs
5. **Auth + audit review (if applicable).**
   Do: parse `auth.log`/`secure` for SSH brute force, accepted logins
   from new IPs, sudo escalation; `audit.log` for execve of attacker
   tooling; cron/systemd for persistence (T1110/T1021/T1053).

### Phase 4: Network Evidence
6. **PCAP / flow analysis.**
   Do: `capinfos` for scope; `tshark`/`zeek` to extract DNS, HTTP(S) SNI,
   and conversation stats. Flag beaconing (regular-interval connections),
   suspicious DNS (DGA/long TXT - possible tunneling), large outbound
   transfers (exfil - T1071/T1048/T1041). Extract C2 IPs/domains as IOCs.

### Phase 5: Correlate into the Super-Timeline
7. **Unify.**
   Do: optionally `log2timeline.py`/`psort.py` to merge EVTX + other
   sources, or merge chainsaw/hayabusa/tshark outputs into the case
   timeline. Slice to `{window}`. Establish the ordered narrative:
   initial access → execution → persistence → cred access → lateral →
   C2 → impact, each row ATT&CK-tagged.

## Output Format

Findings append to `.claude/planning/{case}/INCIDENT_REPORT.md` per
`.claude/skills/_shared/incident-schema.md`.

Specific to this skill:
- **ATT&CK**: T1110 (brute force), T1021/T1570 (lateral), T1059 (exec),
  T1543/T1053 (persistence), T1136/T1098 (account manipulation),
  T1071/T1048/T1041 (C2/exfil).
- **Evidence**: exact tool command + matching log records (event IDs,
  timestamps, source/dest, command lines).
- **IOCs**: source IPs, accounts, C2 domains/IPs, service/task names → IOC
  table.
- **Timeline**: this skill is the primary contributor to the case
  super-timeline - every confirmed event becomes a UTC-normalized row.
- **Recommended response**: D3FEND-mapped (credential reset for abused
  accounts, blocking C2, disabling rogue services) for the operator.

## Quality Check (Self-Review)

- [ ] Each log artifact's SHA-256 verified before analysis
- [ ] All timestamps normalized to UTC; source TZ + skew recorded
- [ ] Logon findings distinguish logon types (2/3/10) and note PtH signals
- [ ] Beaconing claims backed by interval evidence, not a single connection
- [ ] Each finding reproducible (tool command + event IDs) and ATT&CK-tagged
- [ ] Gaps noted where logging was disabled/cleared (1102/wevtutil cl - T1070.001)
- [ ] Skills Run Log row updated `running` → `complete`/`halted:{reason}`

## Common Issues

- **Cleared/rolled logs**: Event 1102 (Security log cleared) or gaps =
  anti-forensics (T1070.001). Record the gap explicitly; absence of logs
  is itself a finding, not "clean".
- **Timezone drift**: EVTX stores UTC, but exported CSVs and Linux logs
  may be local. Mixing them silently corrupts the timeline - normalize
  and label every source.
- **Sigma false positives**: admin tools (PsExec, WMI, PowerShell) are
  used legitimately. Corroborate Sigma hits with account context and
  memory/disk findings before rating Confirmed.
- **NXLog/forwarded gaps**: forwarded logs can drop events under load;
  note coverage limits so "not seen" isn't read as "didn't happen".

## References

- Chainsaw: https://github.com/WithSecureLabs/chainsaw
- Hayabusa: https://github.com/Yamato-Security/hayabusa
- Sigma: https://github.com/SigmaHQ/sigma
- plaso: https://plaso.readthedocs.io/ ; Zeek: https://zeek.org/
- NIST SP 800-61r2 / 800-86; MITRE ATT&CK (T1110, T1021, T1071, T1070)

## Source Methodology

Grounded in `incident-response` (sections 3-4), authored from NIST SP
800-61/86, Sigma, and Chainsaw/Hayabusa documentation. Conversion date:
2026-06-28.
