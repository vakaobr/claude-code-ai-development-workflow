---
name: ad-kerberos-hunter
description: "Tests an authorized Active Directory domain for Kerberos-abuse paths: Kerberoasting (TGS for SPN accounts → offline crack), AS-REP roasting (accounts without pre-auth), and enumeration/proof of unconstrained, constrained (S4U), and resource-based constrained delegation (RBCD) plus shadow-credentials (msDS-KeyCredentialLink) candidates. Consumes ad-recon-hunter's ad-quickwins.md. Use after ad-recon-hunter once internal_pentest is approved and domain credentials are available. Cracking and any impersonation proof are gated. Maps findings to CWE-287/CWE-522/CWE-284 and MITRE T1558. Internal pentest only — requires .claude/security-scope.yaml internal_pentest: approved and credentials from ad_credentials_vault_path. Grounded in redteam-ad-ops."
model: sonnet
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  Bash(netexec:*), Bash(nxc:*), Bash(crackmapexec:*),
  Bash(kerbrute:*), Bash(ldapsearch:*),
  Bash(GetUserSPNs.py:*), Bash(GetNPUsers.py:*), Bash(getTGT.py:*),
  Bash(impacket-GetUserSPNs:*), Bash(impacket-GetNPUsers:*),
  Bash(hashcat:*), Bash(john:*),
  Bash(jq:*), Bash(dig:*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: active-directory
  authorization_required: true
  tier: T1
  profile: internal-ad
  source_methodology: "redteam-ad-ops (RedefiningReality/Cheatsheets, MIT)"
  service_affecting: false
  internal_pentest: true
  composed_from: [redteam-ad-ops, ad-recon-hunter]
---

# AD Kerberos Hunter

## Goal

Prove which Kerberos misconfigurations in an authorized domain lead to
credential compromise or impersonation: roastable accounts whose tickets
can be cracked offline, and delegation primitives that let one principal
act as another. The skill stops at the cheapest defensible proof —
recovering a ticket hash, or demonstrating a delegation primitive is
writable — and hands escalation to the operator. Findings map to
CWE-287 (improper authentication), CWE-522 (weak service-account
passwords), CWE-284 (improper delegation ACLs), MITRE T1558
(Steal/Forge Kerberos Tickets).

## When to Use

- `ad-recon-hunter` has produced `ad-quickwins.md` flagging roastable /
  delegation candidates.
- `internal_pentest: approved` and domain credentials are available.
- The operator wants Kerberos-path coverage before lateral movement.

## When NOT to Use

- No domain credentials yet — run `ad-recon-hunter` first.
- Credential dumping (LSASS/SAM/NTDS) or DCSync — out of scope; separate
  approval + human operator.
- Domain dominance (golden/silver/diamond tickets, forged certs) — these
  are full-compromise actions requiring `domain_dominance: approved`;
  this skill only reaches the precursor proof.
- Web/API targets — wrong tier entirely.

## Authorization Check (MANDATORY FIRST STEP)

1. Read `.claude/security-scope.yaml`. Halt if missing/placeholder.
2. Confirm `internal_pentest: approved` and the domain is in `assets`.
3. Load credentials ONLY from `ad_credentials_vault_path`.
4. **Cracking gate**: offline cracking of recovered tickets requires
   `offline_cracking: approved` in scope (it consumes compute and proves
   weak passwords). If not approved, RECORD the recovered hashes as a
   finding (CWE-522, "crackability untested") and skip the crack step.
5. **Impersonation gate**: any S4U / RBCD / shadow-cred action that
   would mint a usable ticket for another identity requires
   `impersonation_proof: approved`. Without it, prove only that the
   primitive is *writable/abusable* (enumeration + ACL evidence), do not
   mint or use a ticket.
6. Append a `running` row to the Skills Run Log.

## Inputs

- `{issue}`, `{domain}`, `{dc_ip}`
- `{creds}`: vault reference (user/pass or NTLM hash)
- `{candidates}`: path to `ad-quickwins.md` from ad-recon-hunter

## Methodology

### Phase 1: AS-REP Roasting
1. **Request AS-REP for no-preauth accounts.**
   Do: `GetNPUsers.py {domain}/ -dc-ip {dc_ip} -usersfile
   asrep-candidates.txt -format hashcat -no-pass` (or authenticated with
   `{creds}`).
   Vulnerable signal: an AS-REP hash returned (`$krb5asrep$...`).
   Record: FINDING per account (CWE-287). If `offline_cracking:
   approved`, attempt `hashcat -m 18200`; report cracked/uncracked.

### Phase 2: Kerberoasting
2. **Request TGS for SPN accounts.**
   Do: `GetUserSPNs.py {domain}/{user}:{vault} -dc-ip {dc_ip} -request
   -outputfile kerberoast.hashes`.
   Vulnerable signal: TGS hash for a user-class SPN account
   (`$krb5tgs$...`). Machine-account SPNs are not roastable in practice.
   Record: FINDING per service account (CWE-522). If cracking approved,
   `hashcat -m 13100`; flag any cracked service account as High/Critical
   depending on its group memberships (cross-ref BloodHound).

### Phase 3: Delegation Enumeration & Proof
3. **Unconstrained delegation inventory.**
   Do: query `TRUSTED_FOR_DELEGATION` principals (from BloodHound /
   `ldapsearch`). Record candidates; note that exploitation (TGT capture
   via coercion) is operator-driven and needs explicit approval.
4. **Constrained delegation (S4U) inventory.**
   Do: list `msDS-AllowedToDelegateTo` principals. Record the
   delegation target SPNs.
   Proof (only if `impersonation_proof: approved`): demonstrate S4U2Self
   + S4U2Proxy yields a service ticket — capture the ticket metadata as
   evidence, do NOT use it to access the service.
5. **RBCD writability check.**
   Do: check whether `{creds}`' principal has write over
   `msDS-AllowedToActOnBehalfOfOtherIdentity` on any target (BloodHound
   "GenericWrite/GenericAll" edges).
   Vulnerable signal: writable attribute on a target computer.
   Record: FINDING (CWE-284). Do NOT actually write the attribute unless
   `impersonation_proof: approved`; if approved, write → prove → REVERT
   the attribute immediately and document the revert.
6. **Shadow-credentials candidate check.**
   Do: identify targets where the principal can write
   `msDS-KeyCredentialLink`. Record candidates. Minting a PKINIT TGT is
   gated behind `impersonation_proof: approved`; if performed, remove the
   added key credential afterward.

## Output Format

Findings append to `.claude/planning/{issue}/07a_SECURITY_AUDIT.md` per
`.claude/skills/_shared/finding-schema.md`.

Specific to this skill:
- **CWE**: CWE-287 (AS-REP), CWE-522 (Kerberoast weak service passwords),
  CWE-284 (delegation ACL abuse).
- **OWASP/ATT&CK**: MITRE T1558.003 (Kerberoasting), T1558.004 (AS-REP),
  T1558 / T1134 (delegation/impersonation). Tag these in each finding.
- **CVSS**: cracked DA-adjacent service account →
  `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`. Writable RBCD on a server →
  similar, scope-changed.
- **Evidence**: the request command + redacted hash (`$krb5tgs$...`
  truncated), crack result if approved, ACL/edge evidence for delegation.
  Never store full crackable hashes or recovered plaintext in the report
  beyond a truncated proof — keep full material in the engagement vault.
- **Remediation framing**: AD admin — strong (25+ char) managed service
  account passwords or gMSA, set pre-auth on all accounts, remove
  unnecessary SPNs, audit and remove unconstrained delegation, tighten
  write ACLs on computer objects, monitor for TGS requests with RC4.

Updates `STATUS.md` and the Skills Run Log row to `complete`.

## Quality Check (Self-Review)

- [ ] Authorization + cracking + impersonation gates each checked
- [ ] No ticket was minted/used without `impersonation_proof: approved`
- [ ] Any RBCD/shadow-cred write that WAS performed was reverted and the
      revert documented
- [ ] Hashes/plaintext redacted in findings; full material only in vault
- [ ] Cracked accounts cross-referenced to BloodHound for impact rating
- [ ] Skills Run Log row updated `running` → `complete`/`halted:{reason}`

## Common Issues

- **RC4 vs AES tickets**: request RC4 (`-e rc4`) where policy allows for
  faster cracking, but note AES-only environments still yield roastable
  hashes (`-m 19700/19600` in hashcat).
- **Honeypot service accounts**: a too-easy roastable account with high
  privileges may be a decoy/canary. Flag, do not assume, and confirm
  with the client before acting on it.
- **Machine-account SPN false positives**: filter out `$`-suffixed
  accounts — their 120-char random passwords are not crackable.

## References

- The Hacker Recipes — Kerberos: https://www.thehacker.recipes/a-d/movement/kerberos
- Impacket: https://github.com/fortra/impacket
- MITRE ATT&CK T1558: https://attack.mitre.org/techniques/T1558/

## Source Methodology

Grounded in `redteam-ad-ops` (section 2.4) and `ad-recon-hunter`,
distilled from RedefiningReality/Cheatsheets (`RTO I` — Kerberos) —
treated as MIT per author confirmation. Conversion date: 2026-06-27.
