---
name: host-privesc-hunter
description: "Local privilege-escalation assessment on an authorized host where you already have a foothold (operator-provided shell/session). Runs and interprets enumeration - linpeas/LinEnum/pspy/linux-exploit-suggester on Linux; winPEAS/Seatbelt/PowerUp on Windows - and maps findings to concrete escalation paths via GTFOBins (sudo/SUID) and LOLBAS, plus writable services/cron/systemd/scheduled-tasks, kernel-exploit candidates, secrets in files/history, and token/capability abuse. Proves escalation with the least-damage check (id/whoami as root/SYSTEM) and stops. The post-exploitation companion to network-pentest-hunter and the AD chain. Requires .claude/security-scope.yaml red_team_ops.host_privesc: approved and the host in scope. Grounded in redteam-ops."
model: sonnet
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  Bash(linpeas:*), Bash(linpeas.sh:*), Bash(LinEnum:*), Bash(LinEnum.sh:*),
  Bash(pspy:*), Bash(pspy64:*), Bash(linux-exploit-suggester:*), Bash(les.sh:*),
  Bash(winpeas:*), Bash(seatbelt:*), Bash(powerup:*),
  Bash(sudo:-l), Bash(id:*), Bash(whoami:*), Bash(getcap:*),
  Bash(uname:*), Bash(crontab:-l), Bash(systemctl:*),
  Bash(find:*), Bash(ls:*), Bash(cat:*), Bash(grep:*), Bash(jq:*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: privilege-escalation
  authorization_required: true
  tier: T1
  profile: host-privesc
  source_methodology: "redteam-ops (GTFOBins, LOLBAS, PEASS-ng, HackTricks)"
  service_affecting: false
  red_team_ops: true
  composed_from: [redteam-ops]
---

# Host Privilege Escalation Hunter

## Goal

On an authorized host where you already have a low-privilege foothold,
identify and PROVE a path to root/SYSTEM with the least-damage action.
Enumerate the host, interpret the output into concrete escalation
candidates (not a raw tool dump), validate the most reliable one, and
stop at proof (`id`/`whoami` showing elevated context). This is the
post-exploitation companion to `network-pentest-hunter` and the AD chain.
Findings map to CWE-250/CWE-269/CWE-732 and MITRE ATT&CK Privilege
Escalation (TA0004).

## When to Use

- You have an authorized shell/session on an in-scope host
  (`red_team_ops.host_privesc: approved`) and need to assess local
  escalation.
- After `network-pentest-hunter` or an exploit lands initial access, or
  as a configuration-review of a host's privesc exposure.

## When NOT to Use

- Domain/AD escalation (Kerberos, delegation, DCSync) - use
  `ad-kerberos-hunter` / `redteam-ad-ops`.
- Network service testing - use `network-pentest-hunter`.
- Offline cracking of hashes you recover here - hand to `cracking-hunter`.
- A host not in scope, or without an authorized foothold (this skill does
  not gain initial access - it assumes one).

## Authorization Check (MANDATORY FIRST STEP)

1. Read `.claude/security-scope.yaml`. If missing/placeholder, halt.
2. Confirm `red_team_ops.host_privesc: approved` and the host is in scope.
3. Confirm the foothold session was obtained legitimately (prior
   approved step) and the ROE permits post-exploitation on this host.
4. Note that any escalation proof must be least-damage and reverted if it
   changed state; persistence is forbidden.
5. Append a `running` row to the Skills Run Log.

## Inputs

- `{issue}`, `{host}`, `{os}` (linux|windows)
- `{session}`: how the operator provides command execution on the host
- enumeration script locations (linpeas/winpeas, staged read-only)

## Methodology

> Run enumeration, then INTERPRET into ranked candidates. Capture command
> + output excerpt + timestamp per finding.

### Phase 1: Baseline & Context
1. **Who/where am I.**
   Do: `id`/`whoami`, `uname -a` (Linux) or `systeminfo` (Windows), OS
   build/patch level. Record current privileges and patch posture.

### Phase 2: Automated Enumeration
2. **Run the PEAS-suite.**
   Do: `linpeas.sh` (Linux) or `winPEAS` / `Seatbelt` / `PowerUp`
   (Windows), staged read-only and run from a writable temp path.
   Capture the high-signal sections; do not paste the whole dump into
   findings - extract the actionable hits.

### Phase 3: Linux Escalation Candidates
3. **sudo + SUID/SGID via GTFOBins.**
   Do: `sudo -l`; `find / -perm -4000 -type f 2>/dev/null`. Cross-check
   each entry against GTFOBins for a known escalation (e.g. sudo `vim`,
   SUID `find`). Rank by reliability (CWE-250/CWE-732).
4. **Writable services / cron / systemd / PATH.**
   Do: inspect cron (`crontab -l`, `/etc/cron*`), writable systemd units,
   writable scripts run by root, `$PATH` hijack, weak file perms on
   sensitive files (CWE-732).
5. **Kernel & secrets.**
   Do: `linux-exploit-suggester` for kernel-exploit candidates (validate
   carefully - kernel exploits can crash; prefer config paths); grep for
   creds in `~/.bash_history`, config files, `.env`, world-readable
   backups (CWE-522).

### Phase 4: Windows Escalation Candidates
6. **Service & registry misconfig.**
   Do: from winPEAS/PowerUp - unquoted service paths, weak service ACLs
   (can replace binary), AlwaysInstallElevated, modifiable autoruns,
   `SeImpersonate`/`SeBackup` tokens (Potato-class), stored creds
   (cmdkey, registry, GPP) (CWE-269/CWE-250). Cross-check binaries vs
   LOLBAS for living-off-the-land paths.

### Phase 5: Validate (least-damage) & Stop
7. **Prove the most reliable path.**
   Do: execute the single most reliable, lowest-risk candidate to obtain
   an elevated context, then immediately run `id`/`whoami` as proof and
   STOP. Do NOT install persistence, add users, or alter system state to
   demonstrate. If the proof required any change (e.g. a temp file),
   remove it and log the cleanup. Avoid kernel exploits on production
   unless explicitly approved (crash risk).

## Output Format

Findings append to `.claude/planning/{issue}/07a_SECURITY_AUDIT.md` per
`.claude/skills/_shared/finding-schema.md`.

Specific to this skill:
- **CWE**: CWE-250 (execution with unnecessary privileges), CWE-269
  (improper privilege management), CWE-732 (incorrect permissions),
  CWE-522 (protected creds) as applicable.
- **ATT&CK**: Privilege Escalation TA0004 - T1548 (sudo/SUID abuse),
  T1543 (service), T1053 (cron/task), T1068 (kernel exploit), T1078
  (valid accounts from looted creds).
- **Evidence**: the enumeration hit + the validation command + `id`/
  `whoami` proof + cleanup note.
- **Remediation framing**: sysadmin - drop unnecessary sudo/SUID, fix
  file/service ACLs, patch kernel, quote service paths, remove stored
  creds, least-privilege.
- Updates `STATUS.md` and the Skills Run Log.

## Quality Check (Self-Review)

- [ ] `host_privesc` gate verified; foothold was authorized
- [ ] Findings are interpreted candidates, not a raw PEAS dump
- [ ] Each escalation path cross-referenced to GTFOBins/LOLBAS where applicable
- [ ] Only the most reliable, least-damage path validated; proof = id/whoami
- [ ] Kernel exploits avoided on production unless explicitly approved
- [ ] Any state change reverted and cleanup logged; no persistence left
- [ ] Looted credentials redacted; handed to `cracking-hunter` if hashes
- [ ] Skills Run Log row updated `running` → `complete`/`halted:{reason}`

## Common Issues

- **PEAS false positives**: linpeas/winPEAS flag many "potential" items.
  Confirm exploitability (is the writable file actually root-run?) before
  filing - rank, don't dump.
- **Kernel-exploit risk**: a failed kernel exploit can panic the host.
  Treat as last resort, prefer misconfig paths, and require explicit
  approval on production.
- **Container vs host**: inside a container, "root" may be unprivileged
  on the host. Note whether escalation is container-only or breaks out
  (cross-ref `container-hunter`).
- **EDR noise**: enumeration scripts are often flagged; coordinate with
  the client if detection testing is not the goal.

## References

- GTFOBins: https://gtfobins.github.io/ - LOLBAS: https://lolbas-project.github.io/
- PEASS-ng (linpeas/winpeas): https://github.com/peass-ng/PEASS-ng
- HackTricks - Linux/Windows Local Privilege Escalation
- MITRE ATT&CK: T1548, T1068, T1543, T1053

## Source Methodology

Grounded in `redteam-ops` (sections 3-4), authored from GTFOBins, LOLBAS,
PEASS-ng, and HackTricks privesc methodology. Conversion date: 2026-06-28.
