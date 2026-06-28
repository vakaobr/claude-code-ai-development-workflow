---
name: cracking-hunter
description: "Offline password / hash cracking during an authorized engagement using hashcat and John the Ripper. Identifies hash types (hashid/hashcat --identify), runs wordlist + rule + mask attacks against hashes already captured by other skills (ad-kerberos AS-REP/TGS, jwt HS256 secrets, dumped SAM/NTDS/shadow, recovered archives), and reports cracked/uncracked with the password-policy weakness it proves. Offline only - never online brute force. The shared cracking utility the AD and JWT hunters depend on. Requires .claude/security-scope.yaml red_team_ops.offline_cracking: approved. Hashes/plaintext stay in the engagement vault. Grounded in redteam-ops."
model: sonnet
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  Bash(hashcat:*), Bash(john:*), Bash(hashid:*), Bash(hash-identifier:*),
  Bash(cewl:*), Bash(crunch:*), Bash(jq:*),
  Bash(sha256sum:*), Bash(md5sum:*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: cracking
  authorization_required: true
  tier: T2
  profile: cracking
  source_methodology: "redteam-ops (Hashcat wiki, John the Ripper docs)"
  service_affecting: false
  red_team_ops: true
  composed_from: [redteam-ops]
---

# Cracking Hunter

## Goal

Take hashes ALREADY captured by other skills and determine, offline,
which are crackable and how fast - proving weak password policy and the
real-world impact of a hash leak. This is the shared offline-cracking
utility that `ad-kerberos-hunter` (AS-REP/TGS), `jwt-hunter` (HS256
secret), and `host-privesc-hunter` (SAM/shadow/NTDS, recovered archives)
hand off to. It NEVER performs online/credential-stuffing attacks
against a live service. Findings prove CWE-521 (weak password
requirements) / CWE-916 (weak hash) with cracked-vs-uncracked stats.

## When to Use

- Another skill captured hashes and `red_team_ops.offline_cracking:
  approved` is set.
- You need to demonstrate password-policy weakness or the impact of a
  hash/secret disclosure for the client report.

## When NOT to Use

- Online brute force / password spraying against a live login - that is
  ROE-gated service traffic, handled (lockout-aware) by
  `auth-flaw-hunter` / `ad-recon-hunter`, never here.
- Capturing the hashes in the first place - that is the upstream skill's
  job (`ad-kerberos-hunter`, `host-privesc-hunter`, etc.).
- No `offline_cracking` approval, or hashes obtained out of scope.

## Authorization Check (MANDATORY FIRST STEP)

1. Read `.claude/security-scope.yaml`. If missing/placeholder, halt.
2. Confirm `red_team_ops.offline_cracking: approved` (the AD chain may
   also gate via `red_team_extension.offline_cracking` - honor whichever
   the calling engagement set).
3. Confirm the hashes were captured under this engagement's authorization
   (reference the source finding ID). Refuse hashes of unknown origin.
4. All hash material and recovered plaintext stay under the engagement
   vault / case folder - never echo full plaintext into shared reports or
   upload to third-party cracking services.
5. Append a `running` row to the Skills Run Log.

## Inputs

- `{issue}`, `{hashes}`: path to the captured hash file (vault-referenced)
- `{source_finding}`: the FINDING-NNN that captured the hashes
- `{wordlists}` / `{rules}`: approved wordlists (e.g. rockyou) + rule sets
- `{context}`: optional org-specific words for a targeted wordlist

## Methodology

### Phase 1: Identify
1. **Hash-type identification.**
   Do: `hashid` / `hashcat --identify {hashes}` to determine the mode
   (e.g. `-m 1000` NTLM, `-m 13100` Kerberoast TGS, `-m 18200` AS-REP,
   `-m 1800` sha512crypt, `-m 16500` JWT HS256). Record the type and
   count.

### Phase 2: Targeted Wordlist (cheap wins first)
2. **Context wordlist.**
   Do: build an org-specific list with `cewl` over the client's site +
   `{context}` terms; combine with seasons/years/company patterns. Cheap,
   high-yield for real-world policies.

### Phase 3: Attack Ladder
3. **Wordlist + rules.**
   Do: `hashcat -m {mode} {hashes} {wordlist} -r {rules}` (e.g.
   `best64`, `OneRuleToRuleThemAll`) or `john --wordlist --rules`.
   Start with the targeted list, then rockyou, then larger lists.
4. **Mask / brute (bounded).**
   Do: for short/structured spaces, `hashcat -a 3` masks (e.g.
   `?u?l?l?l?l?d?d?d`). Bound by a time budget
   (`red_team_ops.crack_time_budget`); document the keyspace tried so
   "uncracked" is meaningful, not "ran out of time silently".

### Phase 4: Report
5. **Stats + impact.**
   Do: record cracked/total, time-to-crack distribution, and the
   policy weakness it proves (e.g. "37/120 NTLM cracked in 4 min;
   `Summer2026!` x12 → no complexity/rotation enforcement"). For any
   cracked privileged account, cross-reference its rights (BloodHound /
   host context) to rate impact. Keep actual plaintext in the vault;
   the report shows counts + redacted samples (`S….!`).

## Output Format

Findings append to `.claude/planning/{issue}/07a_SECURITY_AUDIT.md` per
`.claude/skills/_shared/finding-schema.md`.

Specific to this skill:
- **CWE**: CWE-521 (weak password requirements), CWE-916 (weak/fast hash
  for storage), CWE-261/CWE-326 as relevant.
- **ATT&CK**: T1110.002 (Password Cracking), supports T1078 (Valid
  Accounts) downstream.
- **Evidence**: hash type + mode, attack run (wordlist/rules/mask +
  keyspace), cracked/total stats, time-to-crack. Plaintext REDACTED in
  the report; full results in the vault, linked by reference.
- **Remediation framing**: identity owner - enforce length/complexity,
  ban breached/seasonal passwords (HIBP), use slow hashes (bcrypt/
  argon2/PBKDF2) for storage, MFA, rotation on the cracked accounts.
- Updates `STATUS.md` and the Skills Run Log.

## Quality Check (Self-Review)

- [ ] `offline_cracking` approved; hash origin tied to a source finding
- [ ] Offline only - no online/live-service attempts
- [ ] Keyspace/time budget documented so "uncracked" is meaningful
- [ ] Plaintext kept in vault; report shows counts + redacted samples only
- [ ] No upload to third-party/online cracking services
- [ ] Cracked privileged accounts rated by their actual rights
- [ ] Skills Run Log row updated `running` → `complete`/`halted:{reason}`

## Common Issues

- **Slow hashes**: bcrypt/argon2/scrypt are intentionally slow - large
  brute is infeasible and that is itself the (good) finding. Report
  resistance, don't burn days.
- **Wrong mode**: misidentified hash type yields zero cracks. Re-verify
  with `--identify` and sample format before concluding "strong".
- **Encoding/format**: Kerberoast/AS-REP/JWT need exact hashcat format;
  malformed input fails silently. Validate one line first.
- **GPU availability**: without a GPU, throughput is low - note the
  hardware so the result reflects your capability, not the password's.

## References

- Hashcat wiki + mode reference: https://hashcat.net/wiki/
- John the Ripper docs: https://www.openwall.com/john/
- OWASP password storage / authentication cheat sheets
- MITRE ATT&CK: T1110.002

## Source Methodology

Grounded in `redteam-ops` (section 4), authored from the Hashcat wiki and
John the Ripper documentation. Conversion date: 2026-06-28.
