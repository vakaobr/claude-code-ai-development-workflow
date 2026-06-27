---
name: mobile-android-hunter
description: "Static security assessment of an authorized Android APK using MobSF (static engine), mobsfscan, and apkleaks. Covers hardcoded secrets / API keys, insecure data storage, exported components (activities / services / receivers / providers) and intent surface, weak crypto, cleartext traffic / network-security-config gaps, dangerous permissions, debuggable / backup-allowed flags, and embedded endpoint URLs. Net-new category — your stack has no mobile coverage. Static-only by default; dynamic instrumentation (Frida / emulator) is out of scope. Use when an Android client app is in scope. Requires .claude/security-scope.yaml with mobile_testing: approved and the artifact under mobile_artifacts. Maps findings to the OWASP MASVS / Mobile Top 10 and CWE-312/CWE-798/CWE-926. Defensive testing only."
model: sonnet
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  Bash(mobsf:*), Bash(mobsfscan:*), Bash(apkleaks:*),
  Bash(apktool:d*), Bash(jadx:*), Bash(unzip:*),
  Bash(trufflehog:*), Bash(jq:*), Bash(python3:*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: mobile-android
  authorization_required: true
  tier: T1
  profile: mobile-sast
  source_methodology: "guardian-cli (MobSF/apkleaks integration pattern), MIT"
  service_affecting: false
  composed_from: []
---

# Mobile Android Hunter

## Goal

Statically assess an authorized Android application package (APK/AAB) for
the most common mobile-specific weaknesses and feed the results into the
canonical finding schema. This is a net-new category for the stack —
none of the 40 existing skills look at mobile clients. Findings map to
OWASP MASVS / OWASP Mobile Top 10 and CWE-312 (cleartext storage),
CWE-798 (hardcoded credentials), CWE-926 (improper export of Android
components).

## When to Use

- An Android client app is in scope and its artifact is listed under
  `mobile_artifacts` in `.claude/security-scope.yaml` with
  `mobile_testing: approved`.
- You want the static layer before (or instead of) a dynamic mobile
  engagement.
- The web/API recon surfaced a mobile app as an alternative channel and
  you want to mine it for hardcoded endpoints / secrets.

## When NOT to Use

- iOS apps (IPA) — this skill is Android-only; build an iOS sibling if
  needed.
- Dynamic analysis (Frida hooking, runtime traffic interception,
  emulator instrumentation) — out of profile; requires a human-approved
  upgrade to a dynamic mobile profile.
- The backend API the app talks to — that is `api-recon` + the API
  hunters (this skill hands off discovered endpoints to them).

## Authorization Check (MANDATORY FIRST STEP)

1. Read `.claude/security-scope.yaml`. Halt if missing/placeholder.
2. Confirm `mobile_testing: approved` and the exact artifact filename /
   hash appears under `mobile_artifacts`.
3. Confirm the MobSF instance is **local/self-hosted** — never upload a
   client APK to the public MobSF instance (the APK is client IP).
4. Append a `running` row to the Skills Run Log.

## Inputs

- `{issue}`: planning folder name
- `{apk_path}`: path to the in-scope APK/AAB artifact
- `{mobsf_url}` / `{mobsf_api_key}`: local MobSF instance (vault ref)

## Methodology

### Phase 1: Package Triage
1. **Unpack & manifest review.**
   Do: `apktool d {apk_path} -o unpacked/` (or `unzip` + `jadx` for
   sources). Read `AndroidManifest.xml`.
   Flag: `android:debuggable="true"`, `android:allowBackup="true"`,
   `usesCleartextTraffic="true"`, dangerous permissions, and every
   `exported="true"` component without a permission guard.
   Record: component/intent surface table.

### Phase 2: MobSF Static Scan
2. **Run the MobSF static engine** (local instance, REST API):
   ```
   curl -F 'file=@{apk_path}' {mobsf_url}/api/v1/upload \
     -H "Authorization:{mobsf_api_key}"        # → returns hash
   curl -X POST {mobsf_url}/api/v1/scan \
     -d "hash={hash}" -H "Authorization:{mobsf_api_key}"
   curl -X POST {mobsf_url}/api/v1/report_json \
     -d "hash={hash}" -H "Authorization:{mobsf_api_key}" \
     -o .claude/planning/{issue}/mobsf-report.json
   ```
   Parse the JSON for: insecure storage, weak crypto, exported
   components, network-security-config, certificate-pinning absence,
   and the security score.
3. **Run mobsfscan** on decompiled source for code-level patterns
   (`mobsfscan unpacked/ --json`).

### Phase 3: Secrets & Endpoints
4. **apkleaks** for embedded URIs, endpoints, and secret patterns:
   `apkleaks -f {apk_path} -o .claude/planning/{issue}/apkleaks.txt`.
5. **trufflehog** over the decompiled tree for verified credential
   patterns: `trufflehog filesystem unpacked/ --json`.
   Record: each hardcoded secret as a FINDING (CWE-798), redacted to
   `first4…last4`. Hand discovered API endpoints to `api-recon` for
   backend testing (note the handoff in the finding).

### Phase 4: Triage
6. Deduplicate MobSF/mobsfscan overlaps into one issue per real defect.
   Downgrade findings that are framework noise (e.g. a debuggable flag in
   a clearly-test build variant) after confirming the build variant.

## Output Format

Findings append to `.claude/planning/{issue}/07a_SECURITY_AUDIT.md` per
`.claude/skills/_shared/finding-schema.md`.

Specific to this skill:
- **CWE**: CWE-312 (cleartext/insecure storage), CWE-798 (hardcoded
  credentials), CWE-926 (improper component export), CWE-327 (weak
  crypto), CWE-319 (cleartext traffic).
- **OWASP**: OWASP MASVS controls + Mobile Top 10 (M1 Improper Credential
  Usage, M2 Inadequate Supply Chain, M4 Insufficient I/O Validation, M9
  Insecure Data Storage, M8 Security Misconfiguration). Tag each finding.
- **Evidence**: the manifest snippet / decompiled code location / MobSF
  rule id, with secrets redacted. Cite the MobSF report path.
- **Remediation framing**: mobile dev — remove hardcoded secrets (use
  Android Keystore / server-issued tokens), set `exported=false` or guard
  with signature permissions, enable network-security-config with pinning,
  disable debuggable/backup in release builds, use authenticated
  encryption for stored data.

Updates `STATUS.md` and the Skills Run Log row to `complete`. Discovered
backend endpoints are written to a handoff note for `api-recon`.

## Quality Check (Self-Review)

- [ ] Artifact in `mobile_artifacts` with `mobile_testing: approved`
- [ ] MobSF instance was local, not the public hosted one
- [ ] No dynamic/Frida instrumentation performed (static profile only)
- [ ] Secrets redacted; discovered endpoints handed to `api-recon`
- [ ] Build-variant confirmed before rating debuggable/backup findings
- [ ] Skills Run Log row updated `running` → `complete`/`halted:{reason}`

## Common Issues

- **Release vs debug variant**: many "criticals" (debuggable, verbose
  logging) exist only in debug builds. Confirm you analyzed the release
  artifact before rating.
- **Third-party SDK noise**: secrets/endpoints often belong to bundled
  SDKs (analytics, ads), not the client's own code. Attribute correctly
  before filing severity.
- **Obfuscated builds**: R8/ProGuard obfuscation limits source-level
  findings; lean on MobSF binary analysis and apkleaks in that case.

## References

- MobSF: https://github.com/MobSF/Mobile-Security-Framework-MobSF
- apkleaks: https://github.com/dwisiswant0/apkleaks
- OWASP MASVS: https://mas.owasp.org/MASVS/
- OWASP Mobile Top 10: https://owasp.org/www-project-mobile-top-10/

## Source Methodology

Cannibalized from the `guardian-cli` (zakirkun/guardian-cli, MIT)
MobSF/apkleaks integration pattern — adapted to this stack's finding
schema and scope-gating model. Conversion date: 2026-06-27.
