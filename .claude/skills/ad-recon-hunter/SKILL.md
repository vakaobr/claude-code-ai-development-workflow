---
name: ad-recon-hunter
description: "Enumerates an authorized internal Active Directory environment: network-service sweep (SMB/LDAP/MSSQL/SNMP), null/guest session harvesting, BloodHound graph collection, and low-noise LDAP queries for users, computers, SPNs, delegation flags, password-not-required accounts, GPP cpassword in SYSVOL, and LAPS-readable hosts. Produces an AD inventory and a prioritized quick-win list that feeds ad-kerberos-hunter. Use as the FIRST internal/AD skill once internal_pentest is approved and engagement credentials (or an anonymous foothold) are available. Maps findings to CWE-200/CWE-522/CWE-284. Internal pentest only — requires .claude/security-scope.yaml internal_pentest: approved and credentials from ad_credentials_vault_path. Grounded in redteam-ad-ops."
model: sonnet
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  Bash(nmap:*), Bash(netexec:*), Bash(nxc:*), Bash(crackmapexec:*),
  Bash(kerbrute:*), Bash(ldapsearch:*), Bash(rpcclient:*),
  Bash(smbclient:*), Bash(showmount:*), Bash(snmp-check:*),
  Bash(bloodhound-python:*), Bash(certipy:*),
  Bash(jq:*), Bash(dig:*), Bash(host:*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: active-directory
  authorization_required: true
  tier: T4
  profile: internal-ad
  source_methodology: "redteam-ad-ops (RedefiningReality/Cheatsheets, MIT)"
  service_affecting: false
  internal_pentest: true
  composed_from: [redteam-ad-ops]
---

# AD Recon Hunter

## Goal

Build the authoritative inventory of an authorized internal Active
Directory environment and surface the cheap escalation paths, without
running any credential attack or post-exploitation action. This is the
internal-network analogue of the web recon tier: it produces the graph
and the target lists that `ad-kerberos-hunter` and (human-driven)
lateral movement consume. Findings map to CWE-200 (information
exposure), CWE-522 (insufficiently protected credentials, e.g. GPP /
descriptions), and CWE-284 (improper access control, e.g. null sessions).

## When to Use

- An internal penetration test is authorized and `internal_pentest:
  approved` is set in `.claude/security-scope.yaml`.
- You have either domain credentials (from `ad_credentials_vault_path`)
  or an unauthenticated foothold on the internal segment.
- The orchestrator (or operator) is starting the AD phase and needs the
  inventory + quick-win list before any Kerberos or credential work.

## When NOT to Use

- External / internet-facing web or API targets — use the web recon
  tier (`web-recon-active`, `api-recon`).
- Kerberoasting / AS-REP / delegation abuse — that is
  `ad-kerberos-hunter` (this skill only flags the candidates).
- Credential dumping (LSASS/SAM/NTDS) or domain dominance — not in this
  skill; those need their own approvals and a human operator.
- Any environment without `internal_pentest: approved`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If it is missing, unparseable, or
   still contains placeholder values, halt and report.
2. Confirm `internal_pentest: approved` is set for this engagement and
   the target subnet / domain appears in `assets`.
3. Load credentials ONLY from `ad_credentials_vault_path`. Never accept
   inline plaintext credentials in the prompt; if asked to, halt.
4. Confirm the engagement window / ROE permits active enumeration now
   (some ROEs restrict scan hours).
5. Append a `running` row to the Skills Run Log in
   `.claude/planning/{issue}/07a_SECURITY_AUDIT.md`.

## Inputs

- `{issue}`: planning folder name
- `{domain}`: target AD domain (e.g. `corp.local`)
- `{dc_ip}`: a reachable domain controller IP
- `{subnet}`: in-scope internal range(s)
- `{creds}`: reference to vault entry (user/pass or NTLM hash) — optional
  if testing the unauthenticated foothold first

## Methodology

### Phase 1: Network & Service Sweep
1. **Host + service discovery** over the in-scope subnet.
   Do: `nmap -sV -Pn --script=safe {subnet}` (stay within ROE scan
   hours). Identify DCs (LDAP/Kerberos/445), MSSQL, SNMP, NFS, web.
   Record: `internal-hosts.md` with host → service matrix.

### Phase 2: Unauthenticated SMB / LDAP Harvest
2. **Null / guest SMB session** against each Windows host.
   Do: `netexec smb {hosts} -u '' -p ''` and `-u guest -p ''`. Capture
   domain name, OS, signing state, and (where allowed) RID-brute the
   user list.
   Vulnerable signal: null/guest session yields users/shares; SMB
   signing not required (relay risk → cross-ref lateral movement).
   Record: FINDING for null-session exposure (CWE-284) and signing-off
   hosts.
3. **Anonymous LDAP** bind probe.
   Do: `ldapsearch -x -H ldap://{dc_ip} -s base namingcontexts`, then
   anonymous user/computer enumeration if the bind succeeds.

### Phase 3: Authenticated Domain Enumeration (if creds available)
4. **BloodHound collection.**
   Do: `bloodhound-python -d {domain} -u {user} -p {vault} -c All
   -ns {dc_ip} --zip`. This is the graph everything else queries.
   Record: store the zip under `.claude/planning/{issue}/bloodhound/`.
5. **Targeted LDAP for quick wins.**
   Do (via `netexec ldap` modules / `ldapsearch`):
   - SPN accounts (`--kerberoasting` candidates list only)
   - AS-REP roastable (`DONT_REQ_PREAUTH`)
   - `PASSWD_NOTREQD` accounts
   - `AdminCount=1` principals
   - User `description` fields containing credential-like strings
   - `TrustedForDelegation` / `msDS-AllowedToDelegateTo` (delegation)
   Record: `ad-quickwins.md` — one row per candidate with the attack it
   enables and which skill executes it.
6. **GPP cpassword sweep** of SYSVOL.
   Do: `netexec smb {dc_ip} -u {user} -p {vault} -M gpp_password`.
   Vulnerable signal: a recoverable `cpassword` → AES-decrypts to a
   plaintext domain credential.
   Record: FINDING Critical/High (CWE-522) — do NOT use the credential
   here; hand it to the operator.
7. **LAPS readability** check.
   Do: `netexec ldap {dc_ip} -u {user} -p {vault} -M laps`.
   Record: FINDING if the test principal can read `ms-Mcs-AdmPwd`.

### Phase 4: ADCS Surface (enumeration only)
8. **Certificate-template enumeration.**
   Do: `certipy find -u {user}@{domain} -p {vault} -dc-ip {dc_ip}
   -stdout` (or `-vulnerable`).
   Record: list ESC1-ESC8 candidate templates as findings (CWE-284);
   exploitation is out of scope for this skill — flag for the operator.

## Output Format

Findings append to `.claude/planning/{issue}/07a_SECURITY_AUDIT.md` per
`.claude/skills/_shared/finding-schema.md`.

Specific to this skill:
- **CWE**: CWE-200 (graph/info exposure), CWE-522 (GPP/description/LAPS
  credential exposure), CWE-284 (null session, anonymous LDAP, ESC
  templates).
- **OWASP**: maps to MITRE ATT&CK rather than OWASP — tag Discovery
  (TA0007) and Credential Access (TA0006) technique IDs in the finding.
- **Evidence**: the exact command + the enumerated result (redact full
  credential values to `first2…last2`); the BloodHound zip path.
- **Remediation framing**: AD admin — disable null/guest sessions,
  enforce SMB signing, remove GPP cpassword and rotate, restrict LAPS
  read ACLs, set pre-auth on roastable accounts, remediate ESC templates.

Also produces (consumed downstream):
- `internal-hosts.md`, `ad-quickwins.md`, `bloodhound/*.zip`
- Updates `STATUS.md` and the Skills Run Log row to `complete`.

## Quality Check (Self-Review)

- [ ] Authorization check passed (`internal_pentest: approved`, creds
      from vault, ROE window respected)
- [ ] No credential attack run (no spray, no roast, no dump) — those are
      downstream skills
- [ ] All recovered credential material redacted in findings and handed
      to the operator, not reused
- [ ] `ad-quickwins.md` lists each candidate with the executing skill
- [ ] Skills Run Log row updated `running` → `complete`/`halted:{reason}`

## Common Issues

- **Lockout from RID-brute / userenum**: RID-brute over SMB does not
  authenticate, but some EDRs alert. `kerbrute userenum` is pre-auth and
  lockout-safe — prefer it for name validation.
- **BloodHound clock skew**: Kerberos collection fails if local time is
  >5 min off the DC. Sync first.
- **Stale graph**: collection is a point-in-time snapshot; note the
  timestamp in findings.

## References

- The Hacker Recipes — AD recon: https://www.thehacker.recipes/
- BloodHound CE docs: https://bloodhound.specterops.io/
- MITRE ATT&CK Discovery (TA0007), Credential Access (TA0006)

## Source Methodology

Grounded in `redteam-ad-ops` (sections 1-2), distilled from
RedefiningReality/Cheatsheets (`Services Testing.md`, `RTO I`) — treated
as MIT per author confirmation. Conversion date: 2026-06-27.
