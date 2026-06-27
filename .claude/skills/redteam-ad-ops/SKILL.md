---
name: redteam-ad-ops
description: >
  Reference skill for internal-network and Active Directory red-team
  operations. Provides a network-service testing matrix (SMB / MSSQL /
  SNMP / NFS / SMTP), the full AD attack lifecycle (Kerberoasting,
  AS-REP roasting, delegation abuse, ADCS ESC, domain trusts, domain
  dominance), Windows credential-access + OPSEC technique maps (LSASS,
  SAM/LSA, NTDS.dit, ticket dumping), C2 infrastructure / EDR-evasion
  patterns, and pentest output-parsing helpers. Load this skill before
  or during any internal/AD engagement to ground the executable
  ad-recon-hunter and ad-kerberos-hunter skills. Knowledge only — no
  execution. The human operator runs the tools.
model: opus
metadata:
  version: 1.0.0
  category: security
  subcategory: internal-ad-redteam
  source: "RedefiningReality/Cheatsheets (treated as MIT per author confirmation 2026-06)"
  grounds_skills: [ad-recon-hunter, ad-kerberos-hunter]
---

# Red Team — Internal & Active Directory Operations Reference

> **Knowledge skill.** This file carries no `allowed-tools` and runs no
> commands. It is the methodology layer that grounds the executable
> `ad-recon-hunter` and `ad-kerberos-hunter` skills. Those skills are
> the ones gated by `.claude/security-scope.yaml` (`internal_pentest:
> approved`). Loading this reference does NOT authorize any activity.

> **Authorization is everything here.** Unlike the web/API hunters,
> the techniques below are post-exploitation and credential-attack in
> nature. They are appropriate ONLY inside an authorized internal
> penetration test with a signed rules-of-engagement, against assets
> declared in scope, using credentials drawn from the engagement vault.
> STOP at proof; do not pivot beyond what the engagement authorizes.

---

## 1. Network Service Testing Matrix

First-contact enumeration and per-service abuse for an internal range.
Pair with `ad-recon-hunter` for execution.

### Discovery and scanning
- Host discovery (ICMP / TCP / UDP sweeps), version + OS detection,
  HTML report export. Tools: `nmap` (`-sV`, `-O`, `--script=safe`),
  `xsltproc` for report rendering.
- Outdated-version triage: extract banners, confirm against CVE data.
  Tools: `nmap`, `curl`, `ssh-audit`.

### Per-service quick map

| Port(s) | Service | First checks | Tooling |
|---|---|---|---|
| 22 | SSH | weak/default creds, algorithm audit | `ssh-audit`, `sshpass`, `netexec ssh` |
| 21 | FTP | anonymous login, weak creds | `nmap`, `netexec ftp` |
| 139/445 | SMB | null/guest session, signing off, share + ACL enum, secrets | `netexec smb`, `rpcclient`, `smbclient`, `Snaffler` |
| 2049 | NFS | exported shares, mount, shadow/VMDK extraction | `showmount`, `rpcinfo`, `kpartx`, `unshadow`+`john` |
| 1433 | MSSQL | login, impersonation, linked-server abuse, NTLM relay | `mssqlclient.py`, `PowerUpSQL`, `SQLRecon` |
| 1521 | Oracle | SID enum, default accounts | `nmap` oracle scripts |
| 3306 | MySQL | weak creds, file read | `netexec`, `nmap` |
| 5432 | Postgres | weak creds, `COPY`/`lo_` file read | `nmap` |
| 6379 | Redis | unauth access, config-set abuse | `redis-cli`, `nmap` |
| 25/465/587 | SMTP | open relay, sender spoof, user enum | `swaks`, `smtp-user-enum` |
| 161/udp | SNMP | community brute, read/write detect | `snmp-check`, `nmap` |
| 3389 | RDP | NLA state, weak creds | `netexec rdp`, `xfreerdp` |
| — | Cisco | Smart Install abuse, type-7 decrypt | `SIET`, `ciscot7.py` |

SMB is the highest-value first target on a Windows network: a null or
guest session frequently yields the domain name, user list (RID brute),
password policy, and reachable shares — the seed data for everything in
section 2.

---

## 2. Active Directory Attack Lifecycle

The order below mirrors a real internal engagement: enumerate, then
escalate by abusing the cheapest misconfiguration available. Execution
of phases 2.1–2.3 lives in `ad-recon-hunter`; 2.4 in
`ad-kerberos-hunter`.

### 2.1 Domain reconnaissance (low-noise, do first)
- Collect the full graph with BloodHound, then query it instead of the
  DC. Tools: `bloodhound-python` / `SharpHound`, BloodHound CE.
- Targeted LDAP: users, computers, groups, SPNs, delegation flags,
  password-not-required, AdminCount, descriptions with creds.
  Tools: `netexec ldap`, `ldapsearch`, `ADSearch`, `PowerView`.
- User enumeration without creds: `kerbrute userenum` against a name
  list (no lockout — pre-auth probing).

### 2.2 Quick wins from enumeration
- **AS-REP roastable** users (no Kerberos pre-auth) → offline crack.
- **Kerberoastable** service accounts (SPN set) → offline crack.
- **Password-not-required** / **password in description** accounts.
- **GPP cpassword** in SYSVOL (`Groups.xml`) → AES-decrypts to plaintext.
- **LAPS-readable** computers (you can read `ms-Mcs-AdmPwd`).

### 2.3 Credential access (gated — engagement-approved only)
- **Password spray** a single weak password across the user list,
  respecting lockout policy (read it first). Tools: `netexec`, `kerbrute`.
- **SMB/LDAP credential validation** to find local-admin reach
  (`netexec smb --local-auth` / pass-the-hash).
- **secretsdump** for SAM/LSA/NTDS once admin reach is proven.

### 2.4 Kerberos abuse (see ad-kerberos-hunter)
- **Kerberoasting** — request TGS for SPN accounts, crack offline.
  `GetUserSPNs.py`, `Rubeus kerberoast`.
- **AS-REP roasting** — `GetNPUsers.py`, `Rubeus asreproast`.
- **Unconstrained delegation** — capture TGTs from connecting privileged
  accounts; coerce auth (`PrinterBug`/`PetitPotam`) to a host you control.
- **Constrained delegation / S4U2Self+S4U2Proxy** — impersonate users to
  configured SPNs. `Rubeus s4u`.
- **Resource-Based Constrained Delegation (RBCD)** — write
  `msDS-AllowedToActOnBehalfOfOtherIdentity` on a target you control.
- **Shadow credentials** — add a `msDS-KeyCredentialLink` (`Whisker`),
  then PKINIT for a TGT (`Rubeus`/`gettgtpkinit`).

### 2.5 ADCS (certificate services) — ESC1-ESC8
- Enumerate templates and CA config. Tools: `Certipy find`, `Certify`.
- Common escalations: ESC1 (SAN in low-priv-enrollable template), ESC8
  (NTLM relay to the CA web-enrollment endpoint), ESC4 (template ACL).
  STOP at certificate issuance proof; do not authenticate as DA.

### 2.6 Lateral movement (proof-only)
Map each MS-RPC protocol to a tool; pick the quietest that proves access:
- MS-SCMR → `psexec.py`, `SharpServiceCommand`
- MS-TSCH → `atexec.py`
- MS-WMI → `wmiexec.py`, `SharpWMI`
- MS-DCOM → `dcomexec.py`, `Invoke-DCOM`
- WS-Man → `evil-winrm`, `winrs`
- RDP → `xfreerdp`, `SharpRDP`

### 2.7 Domain dominance (engagement sign-off required)
Silver / Golden / Diamond tickets, forged certificates (`ForgeCert`),
DCSync (`secretsdump -just-dc`), malicious GPO. These are
full-compromise proofs — only with explicit written authorization, and
documented for cleanup.

---

## 3. Credential Access & Windows OPSEC Technique Map

Two layers, mirrored from the source's paired manuals: the **API layer**
(how it works against the OS) and the **tooling layer** (what to run).
Use the API layer to explain a finding; the tooling layer to reproduce.

| Technique | OS / API primitive | Tooling |
|---|---|---|
| Local→SYSTEM via service | `CreateServiceW`/`ChangeServiceConfigW` | `sc.exe`, `PsExec`, `PowerUp` |
| Token impersonation | `OpenProcessToken`/`DuplicateTokenEx`/`CreateProcessWithTokenW` | `Incognito`, `Tokenvator`, `*Potato` |
| Named-pipe impersonation | `CreateNamedPipe`/`ImpersonateNamedPipeClient` | `*Potato`, RunAsSystem BOFs |
| LSASS dump (userland) | `MiniDumpWriteDump`/`PssCaptureSnapshot`/`ReadProcessMemory` | `procdump`, `comsvcs.dll`, `nanodump`, `pypykatz` |
| LSASS via silent-exit | `RtlReportSilentProcessExit` | `LsassSilentProcessExit` |
| SAM / LSA secrets | `RegSaveKeyEx`, VSS (`CreateVssBackupComponents`) | `reg save`, `secretsdump`, `netexec` |
| Ticket dump (live) | `LsaConnectUntrusted`/`LsaCallAuthenticationPackage` | `Rubeus dump`, `mimikatz` |
| NTDS.dit | local copy / DCSync (DRSUAPI) | `ntdsutil`, `secretsdump -just-dc`, `DSInternals` |
| Keylogging | `SetWindowsHookEx`/`GetAsyncKeyState`/`RegisterRawInputDevices` | `Get-Keystrokes`, `WheresMyImplant` |
| Packet capture | NDIS/PktMon ETW (`EnableTraceEx2`), raw sockets | `netsh trace`, `pktmon`, `Wireshark`/Npcap |

OPSEC note: the source manual exists in a **techniques-only** (API)
edition and a **techniques+tools** edition precisely so an operator can
reason about what an EDR will see (the API surface) before choosing a
tool. Prefer the primitive that generates the least telemetry the
engagement's detection requirements call for.

---

## 4. C2 Infrastructure & EDR Evasion Patterns

From the RTO II material. Reference only — these support a Cobalt Strike
(or equivalent) operation with a signed ROE.

- **Redirector infra**: Apache2 + valid TLS, `mod_rewrite` rules to
  filter on URI/User-Agent, SSH/`autossh` tunnels for HTTPS and DNS
  egress, startup services for persistence of the tunnel.
- **Payload evasion**: reflective-DLL theory, sleep masking, thread-stack
  spoofing, direct syscalls; customize Artifact/Sleep-Mask/Mutator/UDRL
  kits — never ship defaults (the source explicitly warns
  "DO NOT USE AS IS").
- **Post-ex evasion**: BOF memory allocation hygiene, Process Injection
  Kit, ETW patching, inline .NET, PPID spoofing, sane spawn-to targets.
- **Defense bypass**: enumerate/reverse ASR rules, parse WDAC policy and
  abuse trusted signers, circumvent PPL to dump LSASS, load a kernel
  driver with/without DSE bypass (LOLDrivers).
- **Validate your own evasion**: YARA scan payloads (`yara64`), detect
  API hooks (`HookDetector`), `c2lint` your profile, watch for
  `Hunt-Sleeping-Beacons`.

This section is intentionally a pointer map, not a copy-paste arsenal —
operationalize it only within the engagement's evasion requirements.

---

## 5. Output Parsing Helpers

Glue that supports every section above. Keep tool output readable.

- **Linux**: `grep`/`egrep` (e.g. parse open ports from nmap greppable
  output), `cut`/`tr`/`sed` for field extraction and credential
  harvesting, `sort`/`uniq` to dedup IP/hash/DNS lists, `base64`/`iconv`
  for PowerShell `-enc` payloads, redirection + `tee` + here-docs.
- **PowerShell**: `Select-Object`/`Format-Table`/`Format-List`,
  `Where-Object`, `Sort-Object`/`Measure-Object`,
  `Out-File`/`Export-Csv`/`Out-GridView`, `ForEach-Object`, `$_` blocks.
- **AD module pattern**: cmdlet → `-Filter` → format, e.g. enumerate
  unconstrained-delegation principals with `Get-ADUser`/`Get-ADComputer`
  filtering on `TrustedForDelegation`.

---

## References

External:
- OWASP WSTG (network/service testing methodology)
- The Hacker Recipes — Active Directory: https://www.thehacker.recipes/
- HackTricks — AD methodology: https://book.hacktricks.xyz/
- MITRE ATT&CK — Credential Access (TA0006), Lateral Movement (TA0008)
- Certipy / ADCS ESC catalog (SpecterOps "Certified Pre-Owned")

Internal:
- Grounds `ad-recon-hunter` and `ad-kerberos-hunter` (execution).
- Pairs with `offensive-security` (web/API/STRIDE) for full coverage.

## Source & Attribution

Methodology distilled from **RedefiningReality/Cheatsheets**
(https://github.com/RedefiningReality/Cheatsheets), specifically:
`Services Testing.md`, `Parsing Command Output.md`, the two
`OPSEC Reference Manual` editions (Techniques Only + Techniques & Tools),
and `Red Team Operations (RTO) I` and `II`.

The upstream repository ships without a LICENSE file; the author
confirmed (June 2026) it may be treated as **MIT-licensed**. This skill
is a synthesis/restructuring for internal reference, not a verbatim copy,
and credits the source per MIT attribution norms. If the upstream
license is ever formalized differently, revisit this attribution.

Conversion date: 2026-06-27
