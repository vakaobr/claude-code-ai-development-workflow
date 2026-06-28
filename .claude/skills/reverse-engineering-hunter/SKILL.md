---
name: reverse-engineering-hunter
description: "Static + light-dynamic reverse engineering of an authorized binary, firmware image, or malware sample during an engagement: triage (file/strings/FLOSS/capa), firmware carving (binwalk), disassembly/decompilation (Ghidra headless, radare2/rizin), controlled dynamic tracing (gdb+pwndbg, ltrace/strace in a sandbox), and YARA characterization. Surfaces hardcoded secrets/keys, dangerous calls (system/strcpy), auth/licensing logic, crypto usage, and CVE-relevant version markers, mapped to CWE/ATT&CK. Pairs with mobile-android-hunter for unpacked code. Use when a binary/firmware is in scope. Requires .claude/security-scope.yaml red_team_ops.reverse_engineering: approved. Analyzes provided artifacts; runs dynamic only in an isolated sandbox. Grounded in redteam-ops."
model: sonnet
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  Bash(file:*), Bash(strings:*), Bash(binwalk:*), Bash(floss:*),
  Bash(capa:*), Bash(yara:*), Bash(nm:*), Bash(objdump:*),
  Bash(readelf:*), Bash(rabin2:*), Bash(r2:*), Bash(rizin:*),
  Bash(ghidra:*), Bash(analyzeHeadless:*),
  Bash(gdb:*), Bash(ltrace:*), Bash(strace:*),
  Bash(sha256sum:*), Bash(md5sum:*), Bash(jq:*), Bash(python3:*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: reverse-engineering
  authorization_required: true
  tier: T2
  profile: reverse-eng
  source_methodology: "redteam-ops (Ghidra/radare2 docs, practical RE methodology)"
  service_affecting: false
  red_team_ops: true
  composed_from: [redteam-ops]
---

# Reverse Engineering Hunter

## Goal

Understand and assess an authorized binary / firmware / sample: what it
does, what secrets or dangerous behavior it contains, and which
weaknesses it exposes. Work static-first (safest), escalate to controlled
dynamic tracing only in an isolated sandbox. Produce findings — hardcoded
credentials/keys, unsafe APIs, weak crypto, auth/licensing bypass logic,
exploitable patterns, version→CVE markers — mapped to CWE/ATT&CK, with
reproducible analysis steps. Pairs with `mobile-android-hunter` (unpacked
app code) and feeds `exploit-validation-hunter` when a flaw looks
exploitable.

## When to Use

- A binary, firmware image, driver, or malware sample is in scope and
  `red_team_ops.reverse_engineering: approved`.
- After `disk-triage-hunter`/`memory-forensics-hunter` extracts a suspect
  sample that needs characterization, or `mobile-android-hunter` surfaces
  native libs.
- To validate a vendor claim (no hardcoded keys, proper crypto) on a
  delivered binary.

## When NOT to Use

- Source code is available — review the source directly (and
  `secrets-in-code-hunter`); RE is for when you only have the artifact.
- Building a working exploit from an RE finding — hand to
  `exploit-validation-hunter`.
- Live malware detonation for IOC extraction at scale — that is a malware
  sandbox pipeline; this skill does controlled, single-sample triage.

## Authorization Check (MANDATORY FIRST STEP)

1. Read `.claude/security-scope.yaml`. If missing/placeholder, halt.
2. Confirm `red_team_ops.reverse_engineering: approved` and the artifact
   is in scope (in `assets` or `red_team_ops.re_artifacts`).
3. Compute and record `sha256sum` of the artifact (provenance).
4. **Dynamic analysis only in isolation**: any execution (gdb/ltrace/
   strace, running the sample) happens in a disposable, network-isolated
   sandbox VM — never on the operator host or a production network.
   If no sandbox is available, stay static-only.
5. Append a `running` row to the Skills Run Log.

## Inputs

- `{issue}`, `{artifact}` (path), `{type}` (elf|pe|firmware|so|other)
- `{sandbox}`: isolated VM reference for any dynamic step (optional)

## Methodology

> Capture each command + output excerpt as evidence. Static first.

### Phase 1: Triage
1. **Identify + surface strings.**
   Do: `file`, `sha256sum`; `strings -n 8` and `floss` (deobfuscated
   strings) for URLs, paths, keys, error messages; `rabin2 -I` /
   `readelf -h` for arch, protections (NX/PIE/RELRO/canary), imports.
   Record: artifact profile + protection posture.
2. **Capability + packing check.**
   Do: `capa` for capability detection (persistence, C2, crypto, anti-
   analysis); check entropy/`binwalk` for packing/embedded data.

### Phase 2: Firmware Carving (if firmware)
3. **Extract filesystem/components.**
   Do: `binwalk -e` to carve filesystems/bootloaders; enumerate extracted
   configs, keys, and binaries; recurse `strings`/`grep` for creds
   (CWE-798) and hardcoded keys (CWE-321).

### Phase 3: Static Disassembly / Decompilation
4. **Analyze in Ghidra/radare2.**
   Do: `analyzeHeadless` (Ghidra headless) or `r2 -A` to map functions;
   focus on: auth/license checks, input parsing, command construction,
   crypto routines. Flag dangerous calls (`system`/`exec`/`strcpy`/
   `sprintf`/`memcpy` with user input → CWE-78/CWE-120), weak/custom
   crypto (CWE-327), and embedded secrets (CWE-798/CWE-321).
5. **Trace interesting logic.**
   Do: follow xrefs from secrets/dangerous calls to entry points;
   document the call path that an attacker controls.

### Phase 4: Controlled Dynamic (sandbox only, optional)
6. **Confirm behavior safely.**
   Do: in the isolated sandbox, `ltrace`/`strace` to observe file/network/
   exec syscalls; `gdb`+pwndbg to confirm a suspected branch (e.g. a
   licensing bypass at a compare) WITHOUT weaponizing. Capture the proof
   and stop. Never run the sample outside the sandbox.

## Output Format

Findings append to `.claude/planning/{issue}/07a_SECURITY_AUDIT.md` per
`.claude/skills/_shared/finding-schema.md`.

Specific to this skill:
- **CWE**: CWE-798/CWE-321 (hardcoded creds/keys), CWE-78/CWE-120/CWE-787
  (unsafe calls/overflow), CWE-327 (weak crypto), CWE-489 (debug/backdoor),
  + the specific CVE's CWE.
- **ATT&CK**: tag where relevant — T1027 (obfuscation), T1480 (guardrails/
  licensing), T1552 (unsecured credentials).
- **Evidence**: artifact SHA-256, the command/decompiled snippet/address,
  and the controlled-dynamic proof if used.
- **Remediation framing**: dev/vendor — remove hardcoded secrets, use
  vetted crypto, bounds-safe APIs, server-side license/auth checks,
  strip debug backdoors.
- Updates `STATUS.md` and the Skills Run Log.

## Quality Check (Self-Review)

- [ ] `reverse_engineering` gate verified; artifact SHA-256 recorded
- [ ] Static-first; any dynamic step ran ONLY in an isolated sandbox
- [ ] Findings cite concrete addresses/functions/snippets, not "strings suggest"
- [ ] Secrets/keys redacted in the report; full values kept in the vault
- [ ] Exploitable findings handed to `exploit-validation-hunter` (not weaponized here)
- [ ] Skills Run Log row updated `running` → `complete`/`halted:{reason}`

## Common Issues

- **Packing/obfuscation**: UPX/custom packers blank out static analysis —
  unpack (often `upx -d`) or dump from the sandbox before concluding
  "nothing found".
- **Stripped binaries**: no symbols → lean on Ghidra's analysis +
  string/xref pivots; name functions as you go.
- **Back-ported/inlined crypto**: a weak-looking constant may be a test
  vector. Confirm the routine is actually used on real data.
- **Sample safety**: malware can detect VMs and behave benignly, or
  attempt sandbox escape. Snapshot, isolate networking, never reuse the
  sandbox host.

## References

- Ghidra: https://ghidra-sre.org/ — radare2/rizin: https://rizin.re/
- capa: https://github.com/mandiant/capa — FLOSS: https://github.com/mandiant/flare-floss
- pwndbg: https://github.com/pwndbg/pwndbg
- MITRE ATT&CK: T1027, T1480, T1552

## Source Methodology

Grounded in `redteam-ops` (section 4), authored from Ghidra/radare2
documentation and practical RE methodology. Tool shortlist cross-checked
against awesome-pentest (CC-BY-4.0). Conversion date: 2026-06-28.
