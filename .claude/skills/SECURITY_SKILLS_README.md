# Security Skills Library

57 security skills (40 defensive web/API/cloud + 4 internal/mobile/AI
red-team + 7 red-team-ops + 3 DFIR/incident-response + 3 reference) plus
the `security-orchestrator` agent that composes the web/API/cloud set.
Skills are under `.claude/skills/{name}/`;
the agent is at `.claude/agents/security-orchestrator.md`; the
authorization file is `.claude/security-scope.yaml` (template - must be
populated with real company assets before any live use).

## Quickstart

1. **Populate the scope file.** Edit `.claude/security-scope.yaml` with
   real company-owned assets, test credentials vault paths, and an
   authorized OOB listener host. Every skill halts if the scope file
   contains only placeholder values. A fully worked, filled-in example
   (using reserved `example.com`/`contoso.com` domains, covering the
   web/AD/mobile/LLM/red-team-ops/DFIR blocks) is at
   [`.claude/security-scope.example.yaml`](../security-scope.example.yaml)
 - copy from it, never point skills at it.
2. **Run discovery.** `/discover Security assessment of {asset}` creates
   a planning folder at `.claude/planning/{issue-name}/`.
3. **Dispatch the orchestrator.** `@security-orchestrator {issue-name}`
   selects + runs the appropriate hunter skills based on asset type and
   scope. The orchestrator produces `07a_SECURITY_AUDIT.md`.
4. **Alternative (small scope).** `/security {issue-name}` delegates to
   the orchestrator for large/high-risk scopes and falls back to the
   OWASP/STRIDE checklist for M-sized features.

## Skill inventory (40 skills)

### Tier 4 - Recon / Foundation (6 skills)
Run before any hunter. Produce inventory artifacts that hunters consume.

| Skill | Profile | Output |
|---|---|---|
| [web-check-recon](web-check-recon/SKILL.md) | recon-webcheck | `WEBCHECK.md` + `PASSIVE_RECON.patch.md` |
| [web-recon-passive](web-recon-passive/SKILL.md) | passive | `PASSIVE_RECON.md` |
| [web-recon-active](web-recon-active/SKILL.md) | active | `ATTACK_SURFACE.md` |
| [api-recon](api-recon/SKILL.md) | active | `API_INVENTORY.md` |
| [auth-flow-mapper](auth-flow-mapper/SKILL.md) | passive | `AUTH_FLOWS.md` |
| [attack-surface-mapper](attack-surface-mapper/SKILL.md) | active | `CONSOLIDATED_ATTACK_SURFACE.md` |

### Tier 1/2 - Authentication (4 skills)

| Skill | Profile | Covers |
|---|---|---|
| [auth-flaw-hunter](auth-flaw-hunter/SKILL.md) | active | Enumeration, lockout, MFA-skip, default creds, alt-channel drift |
| [session-flaw-hunter](session-flaw-hunter/SKILL.md) | active | Entropy, fixation, cookie flags, logout invalidation, token tampering |
| [jwt-hunter](jwt-hunter/SKILL.md) | active | `alg:none`, HS256 cracking, RS256→HS256 confusion, `kid`/`jku` injection |
| [oauth-oidc-hunter](oauth-oidc-hunter/SKILL.md) | active | redirect-URI validation, state/CSRF, code reuse, flow downgrade |

### Tier 1 - Access Control (2 skills)

| Skill | Profile | Covers |
|---|---|---|
| [idor-hunter](idor-hunter/SKILL.md) | active | Web-app object-ID authorization (CWE-639) |
| [bola-bfla-hunter](bola-bfla-hunter/SKILL.md) | active | API BOLA (API1:2023) + BFLA (API5:2023) |

### Tier 1/2 - Injection (6 skills)

| Skill | Profile | Covers |
|---|---|---|
| [sqli-hunter](sqli-hunter/SKILL.md) | active | Error/Boolean/time/UNION-based SQLi, auth bypass |
| [xxe-hunter](xxe-hunter/SKILL.md) | active | In-band file read, SSRF, blind OOB, XInclude, SVG/OXML |
| [ssti-hunter](ssti-hunter/SKILL.md) | active | Jinja2/Twig/Freemarker/ERB/Velocity/Tornado/Handlebars RCE |
| [command-injection-hunter](command-injection-hunter/SKILL.md) | active | Separator injection, blind time-based/OOB, shell-escape bypass |
| [path-traversal-hunter](path-traversal-hunter/SKILL.md) | active | `../` traversal, LFI, RFI, encoding bypasses, protocol wrappers |
| [deserialization-hunter](deserialization-hunter/SKILL.md) | active | PHP / Java / Python pickle / Ruby Marshal / YAML gadget chains |

### Tier 1/2 - Client-side (6 skills)

| Skill | Profile | Covers |
|---|---|---|
| [xss-hunter](xss-hunter/SKILL.md) | active | Reflected + Stored XSS, context-aware payloads |
| [dom-xss-hunter](dom-xss-hunter/SKILL.md) | active | Source→sink DOM-XSS, postMessage, framework-specific |
| [clickjacking-hunter](clickjacking-hunter/SKILL.md) | passive | XFO / CSP `frame-ancestors` / `SameSite` / UI-redress |
| [csrf-hunter](csrf-hunter/SKILL.md) | active | Token absence, method-swap, Referer bypass, SameSite gaps |
| [open-redirect-hunter](open-redirect-hunter/SKILL.md) | active | Protocol-relative / path-prefix / userinfo / encoding bypasses |
| [cors-misconfig-hunter](cors-misconfig-hunter/SKILL.md) | passive | Origin-reflection + credentials, `null` origin, subdomain confusion |

### Tier 1/2 - API-class (5 skills)

| Skill | Profile | Covers |
|---|---|---|
| [graphql-hunter](graphql-hunter/SKILL.md) | active | Introspection, BOLA via relay IDs, depth DoS, batching, scalar fuzz |
| [mass-assignment-hunter](mass-assignment-hunter/SKILL.md) | active | Blind property injection, HPP, method-swap-with-MA |
| [excessive-data-exposure-hunter](excessive-data-exposure-hunter/SKILL.md) | active | Over-exposing fields, JS-bundle secrets, debug params, error leaks |
| [rate-limit-hunter](rate-limit-hunter/SKILL.md) | active (service_affecting) | Auth brute-force, MFA brute-force, SMS cost amplification, payload stress |
| [owasp-api-top10-tester](owasp-api-top10-tester/SKILL.md) | active | Orchestration: dispatches 8 sub-hunters + produces `API_TOP10_COVERAGE.md` |

### Tier 1/2 - Server-side (3 skills)

| Skill | Profile | Covers |
|---|---|---|
| [ssrf-hunter](ssrf-hunter/SKILL.md) | active | Loopback, internal-IP, cloud metadata, protocol smuggling, DNS rebinding |
| [ssrf-cloud-metadata-hunter](ssrf-cloud-metadata-hunter/SKILL.md) | active | AWS IMDSv1/v2 bypass, GCP v1beta1, Azure metadata - downstream of SSRF |
| [cache-smuggling-hunter](cache-smuggling-hunter/SKILL.md) | active (staging-only, dual-gated) | Cache poisoning via unkeyed headers, CL.TE / TE.CL smuggling |

### Tier 1 - Logic + Cross-cutting (2 skills)

| Skill | Profile | Covers |
|---|---|---|
| [business-logic-hunter](business-logic-hunter/SKILL.md) | active | Workflow bypasses, logical-invalid data, hidden-field tampering, one-time-function reuse |
| [crypto-flaw-hunter](crypto-flaw-hunter/SKILL.md) | passive | Consolidates TLS / cookie / JWT / secret artifacts into `CRYPTO_POSTURE.md` |

### Tier 3 - Cloud / CI/CD / Secrets (5 skills)

| Skill | Profile | Covers |
|---|---|---|
| [aws-iam-hunter](aws-iam-hunter/SKILL.md) | cloud-readonly | Over-privileged roles, exposed keys, IMDSv1, dangling DNS, leaky ARNs |
| [s3-misconfig-hunter](s3-misconfig-hunter/SKILL.md) | cloud-readonly | Public ACLs / policies, missing Block-Public-Access, SSE / versioning / logging gaps |
| [container-hunter](container-hunter/SKILL.md) | cloud-readonly | Privileged pods, permissive SecurityContexts, RBAC, missing NetworkPolicies, Dockerfile anti-patterns |
| [gitlab-cicd-hunter](gitlab-cicd-hunter/SKILL.md) | cicd-readonly | Pipeline secrets, `.git/` leaks, webhook SSRF, privileged runners |
| [secrets-in-code-hunter](secrets-in-code-hunter/SKILL.md) | repo-readonly | trufflehog + gitleaks + custom regex over repo history |

### Tier 2 - Recon-adjacent (1 skill)

| Skill | Profile | Covers |
|---|---|---|
| [subdomain-takeover-hunter](subdomain-takeover-hunter/SKILL.md) | passive | Dangling CNAMEs to unclaimed GitHub / S3 / Heroku / Azure; NS takeover |

### Internal / Mobile / AI - Red-Team Extension (5 skills)

Net-new categories the 40 web/API/cloud hunters do not cover. Sourced
from RedefiningReality/Cheatsheets (MIT, per author) and cannibalized
from guardian-cli (MIT). These run on a **separate track** from the
web-focused `security-orchestrator` (see "Internal/Mobile/AI track"
below) and carry their own scope gates.

| Skill | Profile | Covers |
|---|---|---|
| [redteam-ad-ops](redteam-ad-ops/SKILL.md) | reference (none) | Knowledge layer: network-service matrix, AD attack lifecycle, credential-access/OPSEC maps, C2/EDR-evasion, output parsing. Grounds the AD hunters. |
| [ad-recon-hunter](ad-recon-hunter/SKILL.md) | internal-ad | Internal AD enumeration: service sweep, null/guest harvest, BloodHound graph, LDAP quick-wins (GPP/LAPS/SPN/delegation), ADCS template surface |
| [ad-kerberos-hunter](ad-kerberos-hunter/SKILL.md) | internal-ad | Kerberoasting, AS-REP roasting, delegation (unconstrained/constrained/RBCD) + shadow-cred proof. Cracking & impersonation gated |
| [llm-redteam-hunter](llm-redteam-hunter/SKILL.md) | ai-redteam | Automated garak + PyRIT probe battery against first-party LLM endpoints → OWASP LLM Top 10 |
| [mobile-android-hunter](mobile-android-hunter/SKILL.md) | mobile-sast | Static APK assessment (MobSF + mobsfscan + apkleaks) → OWASP MASVS / Mobile Top 10 |

**New scope-file keys these require** (add to `.claude/security-scope.yaml`):
`internal_pentest: approved`, `ad_credentials_vault_path`,
`offline_cracking: approved`, `impersonation_proof: approved`,
`credential_dumping: approved`, `domain_dominance: approved` (AD);
`llm_endpoints: [...]`, `llm_redteam: approved`,
`llm_redteam_max_requests` (LLM); `mobile_testing: approved`,
`mobile_artifacts: [...]` (mobile).

### Red-Team Ops (8 skills)

Full-scope offensive engagement skills for **proving impact to clients**,
grounded in PTES / NIST SP 800-115 / HackTricks / GTFOBins (authored, not
imported; tool names cross-checked against awesome-pentest CC-BY-4.0).
More aggressive than the web `active` hunters; least-damage proof, no
online brute force, no persistence. Findings go to `SECURITY_AUDIT.md` /
`PENTEST_REPORT.md`. **AV/EDR evasion is intentionally excluded.**

| Skill | Profile | Covers |
|---|---|---|
| [redteam-ops](redteam-ops/SKILL.md) | reference (none) | Engagement methodology (PTES phases), ROE + proof-for-clients, external→internal kill-chain, technique/tool map. Grounds the red-team-ops hunters. |
| [network-pentest-hunter](network-pentest-hunter/SKILL.md) | network-pentest | Non-web infra: full nmap/rustscan/masscan, SMB/SNMP/NFS/DB/mail enum, default-cred checks, version→CVE + least-damage validation |
| [host-privesc-hunter](host-privesc-hunter/SKILL.md) | host-privesc | Local Linux/Windows privesc on an authorized foothold: PEAS enumeration → GTFOBins/LOLBAS/service/cron/kernel paths, least-damage proof |
| [cracking-hunter](cracking-hunter/SKILL.md) | cracking | Offline hashcat/John against captured hashes (AD/JWT/SAM/NTDS); proves weak password policy. The shared cracking utility |
| [reverse-engineering-hunter](reverse-engineering-hunter/SKILL.md) | reverse-eng | Static + sandboxed-dynamic RE of binaries/firmware (Ghidra/radare2/gdb/binwalk/capa): secrets, unsafe calls, weak crypto, auth-bypass logic |
| [exploit-validation-hunter](exploit-validation-hunter/SKILL.md) | exploit-validation | Confirm exploitability with vetted PoCs / pwntools (replica-first, benign proof, stop at proof). Flips Suspected→Confirmed/Not-Exploitable |
| [social-engineering-hunter](social-engineering-hunter/SKILL.md) | social-eng | Authorized phishing/awareness (Gophish; evilginx MFA-phish demo gated). Targets people - separate written consent; never stores real creds |
| [wireless-hunter](wireless-hunter/SKILL.md) | wireless | 802.11 survey, WPA handshake/PMKID capture (→ cracking-hunter), rogue-AP/awareness demos. Runs from a Linux capture host (VM passthrough / Pi); needs RF hardware |

**New scope-file keys these require** (under the `red_team_ops:` block):
`network_pentest`, `network_targets`, `exploit_validation`, `lab_replica`,
`scan_rate`, `host_privesc`, `offline_cracking`, `crack_time_budget`,
`reverse_engineering`, `re_artifacts`, `social_engineering`,
`se_consent_ref`, `se_recipient_list`, `se_evilginx`, `wireless`,
`wireless_targets`, `wireless_workshop_consent`, `wireless_capture_host`.
All default `denied`.

### DFIR / Incident Response (4 skills)

Net-new **defensive** category - the stack's first non-offensive track.
Grounded in NIST SP 800-61/800-86, SANS PICERL, and MITRE ATT&CK/D3FEND
(authored from those sources, not from any awesome-list). Analyzes
**acquired evidence copies read-only**; never acquires, mutates, contains,
or eradicates. Runs as its own track (see "DFIR track" below) and writes
to `INCIDENT_REPORT.md`, not `SECURITY_AUDIT.md`.

| Skill | Profile | Covers |
|---|---|---|
| [incident-response](incident-response/SKILL.md) | reference (none) | Knowledge layer: NIST/PICERL lifecycle, evidence handling + chain of custody, triage decision tree, IOC/ATT&CK model, artifact map. Grounds the DFIR hunters. |
| [memory-forensics-hunter](memory-forensics-hunter/SKILL.md) | dfir-readonly | Volatility 3 over a RAM image: hidden/injected processes (malfind), netscan, DLLs/drivers, cmdlines, credential-access traces |
| [disk-triage-hunter](disk-triage-hunter/SKILL.md) | dfir-readonly | Sleuth Kit + plaso over a disk image: $MFT/registry/Prefetch/tasks/persistence, deleted-file recovery, super-timeline |
| [log-timeline-hunter](log-timeline-hunter/SKILL.md) | dfir-readonly | Chainsaw/Hayabusa (Sigma) over EVTX + Linux/network logs/PCAP: logon anomalies, lateral movement, C2 beaconing, unified UTC timeline |

**New scope-file keys these require** (under a `dfir_scope:` block in
`.claude/security-scope.yaml`): `incident_response`, `case_id`,
`evidence_store_path`, `chain_of_custody_log`, `allow_live_response`,
`external_sandbox`. All default `denied`.

## Tool profiles

All skills reference one of 17 profiles defined in
[_shared/tool-profiles.md](_shared/tool-profiles.md):

- **passive** - `Read, Grep, Glob, WebFetch` (no Bash outside planning/)
- **active** - passive + allowlisted Bash (`curl`, `ffuf`, `nuclei`,
  `arjun`, `nmap --script=safe`, etc.; forbidden: sqlmap, metasploit,
  hydra, nikto)
- **cloud-readonly** - passive + `aws` CLI restricted to `describe-*`,
  `get-*`, `list-*`, `simulate-principal-policy` (no write verbs)
- **cicd-readonly** - passive + `glab` restricted to read-only +
  `git log/show/blame/grep`
- **repo-readonly** - passive + `git log/show/blame/grep/diff` +
  `trufflehog`, `gitleaks detect/protect`
- **internal-ad** - DELIBERATELY breaks the no-credential-attacks rule
  for authorized internal pentests: `netexec`/`crackmapexec`, `kerbrute`,
  impacket, `bloodhound-python`, `certipy`, `hashcat`/`john`. Highest
  blast radius; extra-gated (`internal_pentest: approved`, vault creds,
  cracking/impersonation/dumping/dominance sub-gates)
- **ai-redteam** - `garak`, `pyrit`, `python3`, `curl` against
  first-party LLM endpoints only
- **mobile-sast** - static APK tooling: `mobsf`, `mobsfscan`, `apkleaks`,
  `apktool`, `jadx`, `trufflehog` (no dynamic/Frida)
- **dfir-readonly** - read-only forensics on evidence COPIES: `vol`
  (Volatility 3), Sleuth Kit (`mmls`/`fls`/`icat`), `plaso`, `chainsaw`,
  `hayabusa`, `tshark`/`zeek`, `yara`; hash-verify before analysis, no
  acquisition/mount-rw/containment
- **network-pentest** - infra pentest: full `nmap`/`rustscan`/`masscan`,
  `netexec`, `enum4linux-ng`, `smbmap`, `snmpwalk`, `searchsploit`;
  least-damage validation, no online brute force (`hydra`/`medusa` banned)
- **host-privesc** - local privesc enumeration on an authorized foothold:
  `linpeas`/`winpeas`, `pspy`, `linux-exploit-suggester`, `seatbelt`,
  `sudo -l`, `getcap`; prove with `id`/`whoami`, no persistence
- **cracking** - OFFLINE only: `hashcat`, `john`, `hashid`, `cewl`,
  `crunch`; vault-stored results (hashcat-exempt from the ban, like
  internal-ad)
- **reverse-eng** - `ghidra`/`analyzeHeadless`, `radare2`/`rizin`,
  `gdb`, `binwalk`, `capa`, `floss`, `yara`, `objdump`/`readelf`;
  static-first, dynamic only in an isolated sandbox
- **exploit-validation** - `searchsploit`, `python3` (pwntools), `gdb`,
  `ropper`, `one_gadget`, `checksec`, `nc`/`socat`; replica-first, benign
  proof (no `metasploit`/`msfvenom`, no destructive payloads)
- **social-eng** - `gophish`, `evilginx2`, `python3`, `curl`, `dig`;
  consent + approved-recipient gated, never stores real credentials
- **wireless** - aircrack-ng suite, `kismet`, `hostapd`/`dnsmasq`,
  `bettercap`, `hcxdumptool`, `tshark`; runs on a Linux capture host
  (VM passthrough / Pi), RF hardware required, deauth scoped

## Output contract

All skills append findings to a single canonical file:
`.claude/planning/{issue}/07a_SECURITY_AUDIT.md` using the schema in
[_shared/finding-schema.md](_shared/finding-schema.md). Monotonic
`FINDING-NNN` IDs, append-only, per-finding CWE / OWASP / CVSS +
evidence + remediation.

## Cross-skill dispatch patterns

- `web-check-recon` → `web-recon-passive` → `web-recon-active` /
  `api-recon` → `attack-surface-mapper` (web-check-recon runs first as
  a fast structured first-pass; passive recon consumes its `WEBCHECK.md`
  and adds the OSINT depth it skips). Hygiene candidates hand off to
  `crypto-flaw-hunter` / `clickjacking-hunter` / `session-flaw-hunter` /
  `csrf-hunter`.
- `ssrf-hunter` → `ssrf-cloud-metadata-hunter` → `aws-iam-hunter`
  (SSRF confirmed → IMDS probe → IAM enumeration). Each skill stops
  at its boundary.
- `auth-flow-mapper` → `jwt-hunter` / `oauth-oidc-hunter` /
  `session-flaw-hunter` / `auth-flaw-hunter` (mapper produces
  `AUTH_FLOWS.md` + handoff files).
- `graphql-hunter` → `sqli-hunter` / `command-injection-hunter` (for
  resolver-bound injection candidates).
- `owasp-api-top10-tester` dispatches 8 sub-hunters and produces
  `API_TOP10_COVERAGE.md`.
- `open-redirect-hunter` → `oauth-oidc-hunter` (feeds OAuth-chain
  candidates).
- `secrets-in-code-hunter` → `aws-iam-hunter` (AWS-key validation
  handoff; keys stored as `first4…last4…sha256` hash only).

## Internal / Mobile / AI track

The `security-orchestrator` agent is web/API/cloud-scoped and does NOT
auto-dispatch the 5 extension skills (their blast radius and tooling
differ too much from the harmless-probe model). Run them deliberately:

- **AD / internal**: `redteam-ad-ops` is reference - load it for context.
  Then `ad-recon-hunter` → `ad-kerberos-hunter` (recon produces
  `ad-quickwins.md` that kerberos consumes). Lateral movement, credential
  dumping, and domain dominance remain human-operator-driven even when
  scope-approved. Gate: `internal_pentest: approved`.
- **LLM**: `/redteam-ai` (manual threat model) → `llm-redteam-hunter`
  (automated garak/PyRIT confirmation). The hunter writes into
  `07a_SECURITY_AUDIT.md` and summarizes into `07c_AI_THREAT_MODEL.md`
  without overwriting the manual analysis. Gate: `llm_redteam: approved`.
- **Mobile**: `mobile-android-hunter` (static). Discovered backend
  endpoints hand off to `api-recon` for normal API testing. Gate:
  `mobile_testing: approved`.

## Red-team-ops track

Full-scope offensive engagement, manually driven (not auto-dispatched by
the web orchestrator). Load `redteam-ops` (reference) for methodology +
ROE + proof-for-clients, then follow the kill-chain with the right
hunters:

- **Infra**: `network-pentest-hunter` (non-web service discovery →
  enumeration → least-damage validation). Gate:
  `red_team_ops.network_pentest: approved` (+ `exploit_validation` for PoC).
- **Post-exploitation**: `host-privesc-hunter` (local root/SYSTEM on an
  authorized foothold). Gate: `red_team_ops.host_privesc: approved`.
- **Cracking**: `cracking-hunter` (offline). The AD chain
  (`ad-kerberos-hunter`), `jwt-hunter`, and `host-privesc-hunter` hand
  captured hashes here. Gate: `red_team_ops.offline_cracking: approved`.
- **Reverse engineering**: `reverse-engineering-hunter` (binaries/
  firmware/samples; static-first, dynamic in an isolated sandbox).
  Feeds `exploit-validation-hunter`. Gate: `red_team_ops.reverse_engineering`.
- **Exploit validation**: `exploit-validation-hunter` (prove a Suspected
  finding with a vetted PoC, replica-first, benign proof). `service_affecting`
 - per-invocation OK. Gate: `red_team_ops.exploit_validation: approved`.
- **Social engineering**: `social-engineering-hunter` (phishing / awareness;
  evilginx MFA-demo gated). Targets people - needs `se_consent_ref` +
  `se_recipient_list`. Gate: `red_team_ops.social_engineering: approved`.
- **Wireless**: `wireless-hunter` - runs from a **Linux capture host**
  (VM with USB passthrough, or a Raspberry Pi 4/5; never macOS directly)
  with a monitor-mode adapter (e.g. Alfa AWUS036ACH). Handshakes hand to
  `cracking-hunter`. Rogue-AP/awareness demos need
  `wireless_workshop_consent`. Gate: `red_team_ops.wireless: approved`.

Findings use the offensive finding schema and feed the engagement attack
narrative. **AV/EDR evasion is intentionally out of scope.** Social
engineering and wireless require their own consent/hardware; the agent
plans + analyzes, the operator runs the live part.

## DFIR track

The DFIR skills are **defensive/reactive**, fully separate from the
offensive orchestrator and the offensive scope. They run during an
authorized incident, on acquired evidence copies, and write to
`.claude/planning/{case}/INCIDENT_REPORT.md` (schema:
[_shared/incident-schema.md](_shared/incident-schema.md)) - never to
`SECURITY_AUDIT.md`. Gate: `dfir_scope.incident_response: approved`.

- Load `incident-response` (reference) for lifecycle + evidence-handling
  context, then run the hunters against whatever evidence exists:
  `memory-forensics-hunter` (RAM), `disk-triage-hunter` (disk image),
  `log-timeline-hunter` (EVTX/syslog/PCAP). They cross-corroborate and
  build one UTC super-timeline.
- Every hunter hash-verifies its evidence item before analysis and HALTs
  on mismatch. Containment / eradication / acquisition are operator
  actions, never performed by these skills.

## Validation

```bash
./scripts/validate-skills.sh
```

Checks: file presence, frontmatter fields, required sections, name
matches directory, description length, scope-file reference,
defensive-framing heuristic, forbidden-tool catch, cloud-readonly
write-verb catch, references/ file consistency.

Expected output: **0 errors, 0 warnings**. Validator notes: the reference
skills `offensive-security`, `redteam-ad-ops`, `incident-response`, and
`redteam-ops` are on the exclude list (they have no methodology sections);
`internal-ad` and `cracking` skills are exempt from the `hashcat` ban
(offline cracking is intentional there) - `sqlmap`/`metasploit`/`hydra`/
`nikto` stay banned for every skill. The `dfir-readonly`,
`network-pentest`, and `host-privesc` profiles use no banned tools, so
they need no exemption.

## Authorization model

Summary (full contract in project `CLAUDE.md` > "Security Testing
Scope and Authorization"):

1. Every skill reads `.claude/security-scope.yaml` before outbound
   activity.
2. No testing outside declared `assets`.
3. No destructive payloads without `destructive_testing: approved`
   per asset.
4. OOB listeners must be in scope's allowlist.
5. RCE / credential-theft confirmations STOP at proof - no pivoting.
6. Append-only findings in `SECURITY_AUDIT.md` via the canonical
   schema.
