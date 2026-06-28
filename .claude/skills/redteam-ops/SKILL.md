---
name: redteam-ops
description: >
  Reference skill for full-scope offensive engagements (network/infra
  penetration tests and red-team operations) where you must demonstrate
  and PROVE impact to a client, not just flag findings. Provides the PTES
  / NIST SP 800-115 engagement phases, rules-of-engagement and evidence-
  for-clients discipline (proof capture, screenshots, attack narrative),
  the external→internal kill-chain, and a tool/technique map across
  network pentest, host privilege escalation, offline cracking, reverse
  engineering, exploit validation, social engineering, and wireless. Load
  it before or during any engagement to ground the executable
  network-pentest-hunter, host-privesc-hunter, and cracking-hunter skills
  (and the RE / exploit / social / wireless skills as they land).
  Knowledge only — no execution; the operator runs the tools under signed
  authorization.
model: opus
metadata:
  version: 1.0.0
  category: security
  subcategory: redteam-ops
  grounds_skills: [network-pentest-hunter, host-privesc-hunter, cracking-hunter]
  sources: ["PTES", "NIST SP 800-115", "MITRE ATT&CK", "OSSTMM", "HackTricks", "GTFOBins", "LOLBAS"]
---

# Red-Team Operations Reference

> **Knowledge skill.** No `allowed-tools`; runs nothing. It grounds the
> executable red-team-ops hunters (`network-pentest-hunter`,
> `host-privesc-hunter`, `cracking-hunter`, and the RE / exploit /
> social-engineering / wireless skills as they ship). Those are gated by
> `.claude/security-scope.yaml` (`red_team_ops.*`). Loading this
> authorizes nothing.

> **Authorization and proof are the two pillars.** Every technique here
> runs ONLY under a signed rules-of-engagement against in-scope assets.
> And because the deliverable is client-facing proof, every action is
> captured as reproducible evidence (command + output + timestamp +
> screenshot) that maps to the attack narrative. STOP at the cheapest
> proof of impact; do not cause damage to demonstrate it.

> This sits alongside `redteam-ad-ops` (internal AD specifics) and
> `offensive-security` (web/API/STRIDE). Use those for their domains; use
> this for engagement methodology + the non-web, non-AD techniques.

---

## 1. Engagement Phases (PTES / NIST SP 800-115)

| PTES phase | What happens | This-stack skills |
|---|---|---|
| Pre-engagement | Scope, ROE, authorization, success criteria, emergency contacts | scope file + this reference |
| Intelligence gathering | OSINT, external footprint, attack surface | `web-recon-*`, `api-recon`, OSINT (future) |
| Threat modeling | Map likely paths to client's crown jewels | this reference |
| Vulnerability analysis | Service/version/config weaknesses | `network-pentest-hunter`, web/API hunters |
| **Exploitation** | Prove access (validated, least-damage) | `network-pentest-hunter`, exploit skill (future) |
| **Post-exploitation** | Privesc, loot, lateral, business impact | `host-privesc-hunter`, `cracking-hunter`, `redteam-ad-ops` |
| Reporting | Narrative + evidence + remediation, client-facing | finding schema + this reference |

NIST SP 800-115 maps the same arc to Planning → Discovery → Attack →
Reporting. Whichever the client uses, the rigor is identical.

## 2. Rules of Engagement & Proof-for-Clients

- **Authorization first, always.** Confirm the target is in
  `security-scope.yaml`, the `red_team_ops` gate for the technique is
  `approved`, and the engagement window/ROE permits it now.
- **Least-damage proof.** Demonstrate impact with the safest possible
  action: read one canary record rather than dumping a table; pop
  `whoami`/`id` rather than deploying an implant; screenshot the admin
  panel rather than changing settings. The client needs proof, not harm.
- **Evidence capture for every step** (the hunters enforce this):
  command run, raw output excerpt, UTC timestamp, and a screenshot where
  it strengthens the narrative. Evidence must let the client reproduce
  and let you defend the finding.
- **Attack narrative.** Tie findings into a chain: how an attacker goes
  from external foothold → escalation → crown-jewel access. A chained
  story lands harder with clients than a flat list of CVEs.
- **Stop conditions.** Halt at proof of RCE/DA/data access. Do not
  pivot beyond authorized scope, exfiltrate real customer data, or leave
  persistence. Clean up any artifact you create and log the cleanup.

## 3. The Kill-Chain (external → impact)

1. **Recon** — external footprint, exposed services, leaked creds.
2. **Initial access** — exposed service exploit, valid creds, phishing
   (social-engineering skill, separately authorized).
3. **Execution / foothold** — prove code exec on one host (least-damage).
4. **Privilege escalation** — local root/SYSTEM (`host-privesc-hunter`).
5. **Credential access** — dump + crack offline (`cracking-hunter`),
   then reuse (within scope).
6. **Lateral movement** — pivot to higher-value hosts (`redteam-ad-ops`
   for AD; `network-pentest-hunter` for service pivots).
7. **Impact / objective** — reach the agreed crown jewels; prove and stop.

## 4. Technique → Skill / Tool Map

| Area | Executable skill | Key tooling | Methodology source |
|---|---|---|---|
| Network/infra pentest | `network-pentest-hunter` | nmap, rustscan, masscan, netexec, enum4linux-ng, smbmap, snmpwalk, searchsploit | PTES, NIST 800-115, HackTricks (per-port) |
| Host privilege escalation | `host-privesc-hunter` | linpeas/winpeas, pspy, linux-exploit-suggester, Seatbelt; GTFOBins/LOLBAS lookups | GTFOBins, LOLBAS, PEASS-ng, HackTricks privesc |
| Offline cracking | `cracking-hunter` | hashcat, john, hashid, cewl | Hashcat wiki, JtR docs |
| Reverse engineering | (planned) | Ghidra, radare2, gdb/pwndbg, binwalk | reference-led; pairs with mobile dynamic |
| Exploit validation/dev | (planned) | searchsploit, pwntools, public PoCs (vetted) | PTES exploitation; prefer vetted PoCs over bespoke |
| Social engineering / phishing | (planned, reference-heavy) | Gophish, evilginx2 (separate written consent) | needs its own legal authorization |
| Wireless / RF | (planned, VM/Pi support host) | aircrack-ng, kismet, hostapd, bettercap | runs on a Linux capture host, not macOS |

## 5. Reporting

Red-team-ops findings use the offensive finding schema
(`.claude/skills/_shared/finding-schema.md`) and append to
`.claude/planning/{issue}/07a_SECURITY_AUDIT.md` (or `07b_PENTEST_REPORT.md`
for the engagement narrative). Each finding carries the proof chain,
CWE/ATT&CK mapping, business impact in the client's terms, and
remediation. Build the cross-finding **attack narrative** for the exec
summary — that is what proves value to the client.

## 6. Hard Boundaries (what stays out / reference-only)

- **AV/EDR evasion** — intentionally NOT built (operator tradecraft,
  out of this stack's assessment model).
- **Physical, lock-picking, side-channel, ICS/SCADA** — need hardware /
  on-site presence; treat as reference + a human operator, not agent
  hunters.
- **Social engineering & wireless** — require separate written consent
  (human targets) and physical hardware/a Linux capture host
  respectively; the agent supports analysis, the operator runs the live
  part.

---

## References

- PTES: http://www.pentest-standard.org/
- NIST SP 800-115 — Technical Guide to Information Security Testing
- MITRE ATT&CK: https://attack.mitre.org/
- HackTricks: https://book.hacktricks.xyz/ — GTFOBins: https://gtfobins.github.io/ — LOLBAS: https://lolbas-project.github.io/
- OSSTMM: https://www.isecom.org/OSSTMM.3.pdf

Tool names cross-checked against `enaqx/awesome-pentest` (CC-BY-4.0) as a
gap/shortlist index only; all methodology here is authored from the
authoritative sources above.

Conversion date: 2026-06-28
