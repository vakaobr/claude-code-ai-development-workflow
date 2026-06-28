---
name: memory-forensics-hunter
description: "Analyzes an acquired RAM image (read-only, hash-verified copy) with Volatility 3 during an authorized incident: enumerates running/hidden processes and parent-child anomalies, detects code injection (malfind), lists network connections, loaded DLLs/drivers/services, command lines, registry-in-memory, and cached credentials, and extracts IOCs + suspicious binaries for triage. Maps confirmed activity to MITRE ATT&CK (T1055, T1003, T1543, T1071). Use early in Detection & Analysis when a memory image exists. Requires .claude/security-scope.yaml dfir_scope.incident_response: approved and evidence from dfir_scope.evidence_store_path. Read-only on evidence copies; performs no containment. Grounded in incident-response."
model: sonnet
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  Bash(vol:*), Bash(vol.py:*), Bash(volatility3:*),
  Bash(yara:*), Bash(strings:*), Bash(file:*),
  Bash(sha256sum:*), Bash(md5sum:*), Bash(jq:*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: dfir-memory
  authorization_required: true
  tier: T1
  profile: dfir-readonly
  source_methodology: "incident-response (NIST SP 800-86, Volatility 3 docs)"
  service_affecting: false
  dfir: true
  composed_from: [incident-response]
---

# Memory Forensics Hunter

## Goal

Extract, from an acquired RAM image, the evidence that confirms and
scopes an intrusion: malicious/hidden processes, injected code, C2
connections, persistence loaded in memory, and credential-access traces.
Memory is the most volatile and often most revealing artifact - it holds
unpacked malware, live network state, and command lines that disk does
not. The skill works ONLY on a verified read-only copy and produces
reproducible findings mapped to MITRE ATT&CK. It never contains or
remediates.

## When to Use

- An incident is authorized (`dfir_scope.incident_response: approved`) and
  a RAM image has been acquired for an affected host.
- Early in Detection & Analysis, before or alongside disk triage - memory
  findings steer the rest of the investigation.
- After EDR/alert triage indicates code injection, suspicious processes,
  or live C2 on a host whose memory you captured.

## When NOT to Use

- No memory image (only disk/logs) - use `disk-triage-hunter` /
  `log-timeline-hunter`.
- Acquisition itself (capturing RAM from a live host) - that is an
  operator action with its own tooling and `allow_live_response`
  approval; this skill analyzes an already-acquired image.
- Containment/eradication (killing the process, isolating the host) -   operator-driven, out of scope.
- Deep malware reverse engineering - extract the sample and hand off; this
  skill does triage (strings/YARA/behavioral), not RE.

## Authorization Check (MANDATORY FIRST STEP)

1. Read `.claude/security-scope.yaml`. If missing/placeholder, halt.
2. Confirm `dfir_scope.incident_response: approved` and a `case_id` is set.
3. Resolve the memory image from `dfir_scope.evidence_store_path`.
   Compute `sha256sum` and compare to the acquisition hash in the
   Evidence Register. **If it does not match, HALT** and flag possible
   evidence integrity failure.
4. Confirm you are operating on a COPY, not the original acquisition.
5. Append a `running` row to the case Skills Run Log in
   `.claude/planning/{case}/INCIDENT_REPORT.md`.

## Inputs

- `{case}`: case folder name (e.g. `IR-2026-0042`)
- `{image}`: path to the RAM image copy (under evidence_store_path)
- `{host}`: source hostname for the image
- `{iocs}`: optional - known IOCs / YARA rules to sweep for

## Methodology

> All commands are Volatility 3 (`vol -f {image} <plugin>`), read-only.
> Capture each command + output excerpt as finding evidence.

### Phase 1: Image Context
1. **Confirm image validity / OS.**
   Do: `vol -f {image} windows.info` (or `banners.Banners` /
   `linux.<...>` for Linux). Record OS build - wrong symbol profile
   invalidates everything downstream.

### Phase 2: Process Landscape
2. **Process list + tree.**
   Do: `vol -f {image} windows.pslist`, then `windows.pstree`.
   Flag: unusual parent-child (e.g. `winword.exe`→`cmd.exe`→`powershell`),
   masquerading names (`svch0st.exe`, lsass in wrong path), processes
   with no parent.
3. **Hidden / unlinked processes.**
   Do: `vol -f {image} windows.psscan` and compare to pslist (DKOM /
   unlinked = hidden). Record discrepancies (ATT&CK T1014).
4. **Command lines.**
   Do: `vol -f {image} windows.cmdline`. Capture suspicious args
   (encoded PowerShell, LOLBins, download cradles).

### Phase 3: Injection & Malicious Code
5. **Code injection.**
   Do: `vol -f {image} windows.malfind`. Flag PAGE_EXECUTE_READWRITE
   regions with MZ/shellcode. Dump suspect regions for triage
   (ATT&CK T1055). Run `yara` over dumps / `strings` for IOCs.
6. **DLL / module review.**
   Do: `vol -f {image} windows.dlllist` / `windows.ldrmodules`
   (unlinked DLLs), `windows.modules` / `windows.driverscan` (rogue
   drivers, ATT&CK T1014/T1543.003).

### Phase 4: Network & Persistence
7. **Network connections.**
   Do: `vol -f {image} windows.netscan`. Map listeners + established
   connections to suspicious processes; extract remote IPs/ports as IOCs
   (ATT&CK T1071).
8. **Services & autostart in memory.**
   Do: `vol -f {image} windows.svcscan`; registry run-keys via
   `windows.registry.printkey` on relevant hives (ATT&CK T1543/T1547).

### Phase 5: Credential Access
9. **Credential-theft traces.**
   Do: check for lsass access patterns, `windows.registry.hashdump` /
   `lsadump` availability, Mimikatz-style strings.
   Record evidence of credential dumping (ATT&CK T1003) - note for the
   operator that affected credentials need rotation. Do NOT exfiltrate
   recovered secrets; record only that dumping occurred + which accounts.

### Phase 6: Extract & Sweep
10. **IOC sweep + sample extraction.**
    Do: `vol -f {image} windows.dumpfiles`/`pslist --dump` for suspect
    processes; `yara` with `{iocs}` across the image/dumps. Record hashes
    of extracted samples; store under the case folder, never upload
    externally without `dfir_scope.external_sandbox: approved`.

## Output Format

Findings append to `.claude/planning/{case}/INCIDENT_REPORT.md` per
`.claude/skills/_shared/incident-schema.md`.

Specific to this skill:
- **ATT&CK**: tag each finding (T1055 injection, T1003 credential access,
  T1014 rootkit/hidden, T1543/T1547 persistence, T1071 C2).
- **Evidence**: the exact `vol` command + output excerpt with offsets/
  PIDs; hash of any extracted sample.
- **IOCs**: processes, hashes, IPs, domains, mutexes → the IOC table.
- **Recommended response**: D3FEND-mapped (process termination, host
  isolation, credential rotation) - framed for the operator; this skill
  does not execute it.
- Updates the timeline (process-start times) and Skills Run Log.

## Quality Check (Self-Review)

- [ ] Image SHA-256 verified against the Evidence Register before analysis
- [ ] Correct OS symbol profile confirmed (`windows.info`) first
- [ ] pslist vs psscan compared for hidden processes
- [ ] Every finding has a reproducible `vol` command + ATT&CK tag
- [ ] Recovered credentials NOT exfiltrated - only the fact-of-dumping recorded
- [ ] Extracted samples hashed and kept in-case (no external upload unless approved)
- [ ] Skills Run Log row updated `running` → `complete`/`halted:{reason}`

## Common Issues

- **Wrong/missing symbols**: Volatility 3 needs matching symbol tables;
  an unknown build yields empty plugin output. Confirm with
  `windows.info`/`banners` before concluding "nothing found".
- **Legitimate injection**: some EDR/AV and .NET runtimes show RWX
  regions. Corroborate malfind hits with parent process, network, and
  on-disk artifacts before rating Confirmed.
- **Smear / inconsistency**: images taken from a live, busy host can be
  inconsistent (page smear). Note it; prefer corroboration across plugins.

## References

- Volatility 3 docs: https://volatility3.readthedocs.io/
- NIST SP 800-86 (forensic technique integration)
- MITRE ATT&CK: T1055, T1003, T1014, T1543, T1071
- The Art of Memory Forensics (methodology reference)

## Source Methodology

Grounded in `incident-response` (sections 2-4), authored from NIST SP
800-86 and Volatility 3 documentation. Conversion date: 2026-06-28.