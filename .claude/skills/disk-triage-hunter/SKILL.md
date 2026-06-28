---
name: disk-triage-hunter
description: "Triages an acquired disk image (read-only, hash-verified copy) during an authorized incident using The Sleuth Kit and plaso. Recovers the partition/filesystem layout, deleted files, and key host-forensic artifacts — Windows $MFT/$UsnJrnl, registry hives (Amcache/Shimcache/Run keys), Prefetch, scheduled tasks, services, WMI persistence, browser history, LNK/jumplists; Linux cron/systemd, auth logs, shell history, SSH authorized_keys — and builds a filesystem timeline. Surfaces persistence, execution, and anti-forensics evidence mapped to MITRE ATT&CK. Use when a disk image exists in Detection & Analysis. Requires .claude/security-scope.yaml dfir_scope.incident_response: approved and evidence from dfir_scope.evidence_store_path. Read-only on evidence copies; no containment. Grounded in incident-response."
model: sonnet
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  Bash(mmls:*), Bash(fls:*), Bash(icat:*), Bash(fsstat:*),
  Bash(istat:*), Bash(blkls:*), Bash(tsk_recover:*), Bash(mactime:*),
  Bash(log2timeline.py:*), Bash(psort.py:*), Bash(pinfo.py:*),
  Bash(regripper:*), Bash(yara:*), Bash(strings:*), Bash(file:*),
  Bash(exiftool:*), Bash(sha256sum:*), Bash(md5sum:*), Bash(jq:*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: dfir-disk
  authorization_required: true
  tier: T1
  profile: dfir-readonly
  source_methodology: "incident-response (NIST SP 800-86, Sleuth Kit / plaso docs)"
  service_affecting: false
  dfir: true
  composed_from: [incident-response]
---

# Disk Triage Hunter

## Goal

From an acquired disk image, recover the host-forensic artifacts that
establish how an intrusion executed, persisted, and what it touched —
and assemble a filesystem timeline. This is the disk-side companion to
`memory-forensics-hunter`: memory shows the live state, disk shows the
durable record (persistence, execution history, deleted droppers). The
skill works ONLY on a verified read-only copy, never mounts the original
read-write, and produces reproducible, ATT&CK-tagged findings. It does
not contain or eradicate.

## When to Use

- An incident is authorized and a disk image (or forensic copy of key
  artifacts) exists for an affected host.
- During Detection & Analysis to establish persistence, execution
  history, and file-level scope.
- After memory analysis flags a process/path you need to corroborate on
  disk, or when only disk evidence is available.

## When NOT to Use

- Live disk acquisition / imaging — operator action, not this skill.
- Memory-only or log-only evidence — use the sibling skills.
- Full-disk malware RE — extract the artifact and hand off; this is triage.
- Any write/repair/mount-rw operation on evidence — forbidden by profile.

## Authorization Check (MANDATORY FIRST STEP)

1. Read `.claude/security-scope.yaml`. If missing/placeholder, halt.
2. Confirm `dfir_scope.incident_response: approved` and a `case_id`.
3. Resolve the image from `dfir_scope.evidence_store_path`, compute
   `sha256sum`, compare to the acquisition hash in the Evidence Register.
   **Mismatch → HALT** (integrity failure).
4. Confirm analysis is on a COPY; never mount the source read-write
   (use TSK directly on the image, or loop-mount `ro,noexec`).
5. Append a `running` row to the case Skills Run Log.

## Inputs

- `{case}`: case folder name
- `{image}`: path to the disk image copy
- `{host}` / `{os}`: source host + OS family (drives artifact set)
- `{iocs}`: optional — IOCs / YARA rules / suspect paths from prior phases

## Methodology

> Use TSK directly against the image (no rw mount). Capture each command
> + output excerpt as evidence.

### Phase 1: Layout & Filesystem
1. **Partition + filesystem map.**
   Do: `mmls {image}` (partition offsets), then `fsstat -o {offset}
   {image}`. Record volumes, FS type, and the sector offset used for all
   later `-o` calls.

### Phase 2: Filesystem Timeline & Deleted Files
2. **Body file → timeline.**
   Do: `fls -r -m C: -o {offset} {image} > bodyfile`; then
   `mactime -b bodyfile -d -y > fs_timeline.csv`. This is the MAC(b)
   timeline; fold into the case super-timeline.
3. **Deleted-file recovery (targeted).**
   Do: `fls -rd -o {offset} {image}` to list deleted entries; `icat` /
   `tsk_recover` to recover specific suspect files (droppers, staged
   archives) to the case folder. Hash each (ATT&CK T1070 anti-forensics
   if key artifacts were wiped).

### Phase 3: Execution Evidence (Windows)
4. **Program-execution artifacts.**
   Do: extract + parse Prefetch (`C:\Windows\Prefetch`), Amcache
   (`Amcache.hve` via regripper), Shimcache (SYSTEM hive), SRUM. Record
   first/last-run + paths of attacker tooling (ATT&CK T1204/T1059).
5. **Registry persistence.**
   Do: `icat` the hives (SYSTEM/SOFTWARE/NTUSER) and run `regripper`
   plugins for Run/RunOnce, Services, Winlogon, IFEO, COM hijack
   (ATT&CK T1547/T1543/T1546).

### Phase 4: Persistence & Config (cross-OS)
6. **Scheduled tasks / services / WMI (Windows).**
   Do: parse `C:\Windows\System32\Tasks`, services from SYSTEM hive, WMI
   repository (`OBJECTS.DATA`) for event-consumer persistence
   (ATT&CK T1053/T1543/T1546.003).
7. **Linux/macOS persistence (if applicable).**
   Do: examine `/etc/cron*`, systemd units, `~/.bash_history`,
   `~/.ssh/authorized_keys`, `/etc/passwd`+shadow, launch agents/daemons
   (ATT&CK T1053/T1098/T1136).

### Phase 5: User & Web Artifacts
8. **Browser + LNK + recent files.**
   Do: recover browser history/downloads, LNK/jumplists, `$Recycle.Bin`,
   recent-docs — to establish initial access (phishing download) and
   data-staging (ATT&CK T1566/T1074).

### Phase 6: Super-Timeline & IOC Sweep
9. **plaso super-timeline (optional, high-value).**
   Do: `log2timeline.py --storage-file {case}.plaso {image}`; then
   `psort.py -o l2tcsv {case}.plaso > supertimeline.csv` (optionally
   `--slice` around the incident window). This unifies FS + registry +
   evtx + browser into one timeline.
10. **YARA / string sweep.**
    Do: `yara` with `{iocs}` over recovered files; `strings`/`exiftool`
    on suspect binaries/docs. Record matches + hashes.

## Output Format

Findings append to `.claude/planning/{case}/INCIDENT_REPORT.md` per
`.claude/skills/_shared/incident-schema.md`.

Specific to this skill:
- **ATT&CK**: T1547/T1543/T1546/T1053 (persistence), T1204/T1059 (exec),
  T1070 (indicator removal/anti-forensics), T1566 (initial access),
  T1074 (staging).
- **Evidence**: exact TSK/regripper/plaso command + output excerpt +
  artifact path/offset; hash of any recovered file.
- **IOCs**: file paths, hashes, registry keys, task names, URLs → IOC table.
- **Timeline**: contribute FS + super-timeline rows (UTC).
- **Recommended response**: D3FEND-mapped persistence removal / re-image
  guidance, for the operator. This skill does not action it.

## Quality Check (Self-Review)

- [ ] Image SHA-256 verified before analysis; never mounted rw
- [ ] Partition offset confirmed (`mmls`/`fsstat`) before `-o` calls
- [ ] Timeline normalized to UTC; clock skew noted
- [ ] Each finding has a reproducible command + ATT&CK tag
- [ ] Recovered samples hashed, kept in-case (no external upload unless approved)
- [ ] Anti-forensics (wiped/timestomped artifacts) explicitly checked (T1070)
- [ ] Skills Run Log row updated `running` → `complete`/`halted:{reason}`

## Common Issues

- **Timestomping**: `$STANDARD_INFORMATION` vs `$FILE_NAME` timestamp
  mismatch in `$MFT` indicates timestomping (T1070.006) — compare both;
  don't trust SI times alone.
- **Offset errors**: forgetting `-o {offset}` runs TSK against the wrong
  volume and returns nothing. Always derive offset from `mmls` first.
- **Encrypted volumes** (BitLocker/LUKS): need the recovery key (from
  memory image or escrow) before triage — note as a blocker if absent.

## References

- The Sleuth Kit / Autopsy: https://www.sleuthkit.org/
- plaso / log2timeline: https://plaso.readthedocs.io/
- NIST SP 800-86; SANS Windows Forensic Analysis poster
- MITRE ATT&CK: T1547, T1543, T1053, T1070, T1204, T1566

## Source Methodology

Grounded in `incident-response` (sections 2-3), authored from NIST SP
800-86, Sleuth Kit, and plaso documentation. Conversion date: 2026-06-28.
