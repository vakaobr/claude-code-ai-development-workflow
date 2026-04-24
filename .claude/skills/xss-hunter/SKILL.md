---
name: xss-hunter
description: "Tests user-reflecting endpoints for Reflected XSS (Type 1 — single request/response) and Stored XSS (Type 2 — persisted payload executed later by any viewer). Covers syntactic-context analysis (HTML body / attribute / JS block / URL), tag breakout, attribute breakout, event handlers, `javascript:` pseudo-URLs, and WAF evasion. Use when the target reflects user input (search terms, profile fields, comments, error pages, custom headers) into HTML responses; when probes like `XSS_MARKER` appear unencoded in source; or when forms / APIs feed rendered content. Produces findings with CWE-79 mapping, context-specific PoCs, and output-encoding + CSP remediation. Defensive testing only, against assets listed in .claude/security-scope.yaml."
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
  subcategory: client-side
  authorization_required: true
  tier: T1
  source_methodology: "Guia Mestre de Vulnerabilidades XSS_ Detecção e Mitigação.md"
  service_affecting: false
  composed_from: []
---

# XSS Hunter

## Goal

Test user-reflecting endpoints for Reflected (Type 1) and Stored
(Type 2) Cross-Site Scripting — flaws where user-controlled input
reaches a response body or persisted store without proper
context-aware encoding, allowing script execution in another
user's browser. This skill implements WSTG-INPV-01, WSTG-INPV-02,
and maps findings to CWE-79 (Improper Neutralization of Input
During Web Page Generation). The goal is to give the frontend /
backend team a concrete list of reflection points by syntactic
context with targeted PoCs and context-appropriate remediation
(HTML encoding, attribute encoding, JS-string encoding, CSP).

## When to Use

- The target reflects user input in server-generated HTML: search
  terms, profile fields, error messages, comment threads,
  usernames, email addresses.
- Input stored in databases / files is rendered back to users
  later (Stored XSS surface: profiles, comments, messages,
  admin-viewed tickets).
- Custom HTTP headers (Referer, User-Agent) get echoed in pages
  (e.g., analytics dashboards, error pages).
- `web-recon-active`'s spidering surfaced forms with reflection.
- The orchestrator selects this skill for client-side testing.

## When NOT to Use

- For pure client-side JavaScript source→sink analysis (no server
  reflection) — use `dom-xss-hunter`.
- For server-side template injection that looks like XSS but is
  actually RCE — use `ssti-hunter`.
- For CSRF (state-change via browser trust, no script execution)
  — use `csrf-hunter`.
- For Client-Side Template Injection in AngularJS / Vue where the
  outcome is XSS but the root cause is template evaluation in the
  browser — can be handled here, but flag in `references/gaps.md`
  for a dedicated CSTI skill.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or
   doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND
   its `testing_level` is `active`.
3. XSS confirmation uses ONLY harmless in-page evidence: a simple
   `alert(document.domain)` or innocuous DOM marker. NEVER fire:
   - Cookie-exfil to external hosts (unless the destination is the
     scope's authorized OOB listener)
   - Session-token-stealing keyloggers
   - Payloads that auto-submit forms or change state
   - Persistent beacons that call back periodically
4. For Stored XSS, use fields that you can CLEAN UP after testing
   (test profiles, test comment boards). NEVER post Stored XSS
   payloads into admin-viewable tickets or support channels that
   real employees will open.
5. Never test against admin-panel paths where an admin opens the
   page — that becomes a live XSS against a human operator.
   Restrict Stored XSS tests to user-visible surfaces.
6. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with
   status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific reflection points
- `{user_a}`: authenticated session for stored-XSS fields that
  require login
- `{oob_listener}`: authorized OOB listener URL (from scope) for
  CSP-bypass / exfil-PoC variants

## Methodology

### Phase 1: Identify Reflection Points

1. **Alphanumeric probe injection** [WAHH, Ch 12, p. 453]

   Do: For each user-controllable parameter, inject a unique
   benign marker and search response bodies + headers:
   ```
   XSS_MARKER_<random-nonce>
   ```

   Also test less-obvious entry points:
   - Cookies / custom headers (`X-Custom-Field`)
   - Referer / User-Agent (if echoed anywhere)
   - HTTP 404 / 500 error pages (reflect the URL)
   - File-upload metadata (filename reflected in response)

   Vulnerable signal: Marker appears unmodified in response
   source.

   Record: `.claude/planning/{issue}/xss-reflections.md` with
   (parameter, endpoint, marker found at location).

2. **Analyze syntactic context** [WAHH, Ch 12, p. 487]

   Do: For each reflection, identify the context in the response:
   - **HTML body** between tags: `<p>{input}</p>`
   - **HTML attribute**: `<a href="{input}">`
   - **JS string**: `var x = "{input}";`
   - **JS block**: `<script>var x = {input};</script>`
   - **URL context**: `<a href="{input}">click</a>` where
     `javascript:` is a scheme
   - **CSS context**: `<style>.x { color: {input} }</style>`

   Record: Per-reflection context; determines the payload template.

### Phase 2: Context-Specific Probes

3. **HTML-body context — tag injection**
   [Bug Bounty Bootcamp, Ch 6]

   Do: For HTML-body reflections, inject:
   ```
   <script>alert(document.domain)</script>
   <img src=x onerror=alert(document.domain)>
   <svg onload=alert(document.domain)>
   <iframe srcdoc="<script>alert(1)</script>">
   ```

   Vulnerable response: An `alert(...)` fires when loading the
   page, confirmed visually AND via DevTools Elements pane showing
   the injected node.

   Not-vulnerable response: Tags HTML-encoded to
   `&lt;script&gt;...`; rendered as literal text.

4. **HTML-attribute context — attribute breakout**
   [WAHH, Ch 12]

   Do: For reflections inside an attribute (e.g., `value="...{input}..."`):
   ```
   " onfocus=alert(1) autofocus "
   "><script>alert(1)</script>
   "><img src=x onerror=alert(1)>
   ```

   Note: if the attribute is already in single quotes, swap to
   `'`.

   Vulnerable response: The injection breaks out of the attribute
   and introduces either an event handler or a new tag.

5. **JavaScript-string context — string breakout** [WAHH, Ch 12, p. 487]

   Do: For reflections inside a JS string literal (`var x =
   "...{input}..."`):
   ```
   ";alert(1)//
   '-alert(1)-'
   \\";alert(1)//
   `-alert(1)-`
   ```

   Vulnerable response: Breakout closes the string and executes
   the injected script.

6. **JavaScript-block context — direct injection**
   [XSS Cheat Sheet]

   Do: For reflections in a `<script>` block where input is
   unquoted (e.g., `<script>let userId = {input}</script>`):
   ```
   alert(1)
   alert(1)//
   ```

   Vulnerable response: Direct execution — no breakout needed.

   Record: Per-context finding.

7. **URL-context — pseudo-protocol** [XSS Cheat Sheet]

   Do: For reflections in attributes that become URLs (`href`,
   `src`, `action`, `formaction`):
   ```
   javascript:alert(document.domain)
   data:text/html,<script>alert(1)</script>
   vbscript:msgbox(1)   (legacy IE only)
   ```

   Vulnerable response: The link / form submission executes
   JavaScript. May require user click depending on attribute.

### Phase 3: Stored-XSS Confirmation

8. **Persisted payload + second-viewer test**
   [WAHH, Ch 12]

   Do: For fields that persist (profile bio, comments, messages,
   names), inject a context-appropriate payload as `{user_a}`.
   Then view the rendering page as `{user_b}` (OR incognito /
   different browser as guest if publicly visible).

   Vulnerable response: Payload fires when the second viewer
   opens the page — confirms persistence AND cross-user
   execution.

   **Cleanup**: After confirmation, remove the stored payload
   (edit the field to a safe value) or escalate for cleanup.

### Phase 4: Filter / Sanitizer Bypass

9. **Case / encoding / concatenation evasion** [WSTG v4.2]

   Do: If clean payloads are filtered, retry with:
   - Mixed case: `<ScRiPt>alert(1)</ScRiPt>`
   - Case-insensitive regex bypass: `<SvG/oNlOad=alert(1)>`
   - HTML entity encoding: `&#x3c;script&#x3e;`
   - Double-URL-encoding: `%253Cscript%253E`
   - JavaScript concatenation: `<scr<script>ipt>`
     (double tag to survive simple stripping)
   - Unicode escapes: `<script>`
   - Null byte: `<scri%00pt>`

   Vulnerable response: Bypassed filter — payload executes.

10. **Polyglot payload**
    [XSS Cheat Sheet, p. 9]

    Do: For unknown contexts or when you can't determine the
    syntactic position:
    ```
    javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
    ```

    Vulnerable response: Fires in at least one context — narrow
    down to which context and file a context-specific cleaner
    finding.

### Phase 5: CSP and Defensive-Header Check

11. **CSP header audit** [WSTG v4.2]

    Do: Inspect the page's Content-Security-Policy header. Flag:
    - CSP absent
    - `default-src *` or `unsafe-inline` in script-src (allows
      injected inline scripts)
    - `unsafe-eval` (allows `eval` + injected code)
    - Permissive domain list (allows attacker-controlled
      third-party script hosts)
    - Nonce-based policy where the nonce is predictable

    Vulnerable response: Even an otherwise-blocked XSS can
    execute if CSP has these gaps. Cross-reference
    `crypto-flaw-hunter` if secrets are in scope.

## Payload Library

Full per-context catalog in `references/payloads.md`. Categories:

- **HTML-body tag injection**: `<script>`, `<img onerror>`,
  `<svg onload>`, `<iframe srcdoc>`
- **Attribute breakout**: `" onX=Y` variants per event handler
- **JS-string breakout**: `";`, `'-`, `` `- ``, backslash variants
- **URL pseudo-protocols**: `javascript:`, `data:`, `vbscript:`
- **Filter evasion**: mixed case, HTML entities, URL encoding,
  concatenation, unicode
- **Polyglots**: context-agnostic multi-break payloads
- **CSP-bypass notes**: script-gadget references (Angular, Vue,
  jQuery) for CSP-nonce-only policies

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-79 (XSS). For Stored XSS specifically, distinguish
  via subcategory (Reflected vs Stored) in the finding Summary.
  For CSP gaps that allow XSS, add CWE-693 (Protection Mechanism
  Failure).
- **OWASP**: WSTG-INPV-01 (Reflected), WSTG-INPV-02 (Stored). For
  APIs, API8:2023 (Security Misconfiguration) if it's a CSP gap.
  A03:2021 (Injection).
- **CVSS vectors**: Reflected XSS with session-hijack potential —
  `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`. Stored XSS admin-
  reachable — `...UI:R/S:C/C:H/I:H/A:N`. Reflected XSS without
  session impact (informational) — `...C:L/I:L/A:N`.
- **Evidence**: the reproducing URL (for Reflected) or the stored-
  field-contents + viewer URL (for Stored); screenshot or DevTools
  evidence of execution; the syntactic context identified.
- **Remediation framing**: frontend + backend. Include:
  - Context-aware output encoding per framework (Django
    `{{ var }}`; React default text; Vue `{{ }}` default;
    Angular `[innerText]`; explicit HTML-entity encoding where
    text)
  - `v-html` / `dangerouslySetInnerHTML` avoidance
  - DOMPurify wrapper for unavoidable HTML rendering
  - Strict CSP with nonces (not `unsafe-inline`)
  - Cookie `HttpOnly` to prevent script-based cookie theft
    (cross-reference `session-flaw-hunter`)
  - Auto-escape configuration per template engine

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every finding identifies the syntactic context (HTML body /
      attribute / JS-string / URL / CSS)
- [ ] Every confirmed-XSS finding has execution evidence, not just
      reflection (DevTools or alert screenshot)
- [ ] Every Stored XSS was cleaned up after confirmation (field
      reverted or escalated for cleanup)
- [ ] No exfil-to-external-host payloads fired unless the host
      was the scope's OOB listener
- [ ] No Stored payloads were posted into admin-only-viewed
      surfaces
- [ ] Filter-bypass findings note what the filter was doing before
      the bypass
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Inert sink reflection**: The payload reflects into the HTML
  but is assigned to a safe property like `textContent` via the
  frontend after initial render. Browser's DOM shows literal text,
  not an executed script. Confirm execution in DevTools; reflection
  alone isn't XSS.

- **Browser XSS filter blocks**: Legacy Chrome/IE had auditor-
  level filters that blocked some reflected XSS. Modern browsers
  (Chrome 78+, Firefox) removed these. Test in current browsers
  to avoid false negatives.

- **Self-XSS**: Payload requires the victim to paste a complex
  string into their own browser console or form. Not a
  deliverable attack by itself — only file if you can pair it
  with a delivery vector (clickjacking, deceptive social
  engineering).

- **CSP blocks the harmless probe but real attacker bypasses**:
  A strict CSP blocks `alert(1)` from a reflected payload — but
  attackers with motivation can use data: URIs, script gadgets,
  or CSP-allowlisted CDNs. CSP mitigates but doesn't eliminate
  — file the XSS finding AND the CSP-bypass potential
  separately.

- **Stored XSS in admin-only view**: The payload stores but only
  fires when an admin opens an admin panel. Severity is very
  high (privileged-user XSS leads to admin takeover). However,
  during testing, DO NOT leave the payload stored — clean up.

- **Mutation XSS (mXSS)**: Browser HTML parsing mutates input
  between server sanitization and DOM representation. Sanitizers
  correct at serialization-time fail. Advanced mXSS tests need a
  dedicated harness — note candidates here, refer to PortSwigger
  research.

- **Framework auto-escape assumed but bypassed**: Modern
  frameworks auto-escape by default (React text, Django
  `{{ var }}`). Bugs arise when developers use
  `dangerouslySetInnerHTML` / `|safe` / `v-html` explicitly.
  Focus testing where these escape hatches are used.

## References

- `references/payloads.md` — full per-context payload catalog
  including filter-evasion families and polyglots

External:
- WSTG-INPV-01: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting
- WSTG-INPV-02: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting
- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- OWASP XSS Prevention Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- PortSwigger XSS cheat sheet:
  https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia Mestre de Vulnerabilidades XSS_ Detecção e Mitigação.md`

Grounded in:
- The Web Application Hacker's Handbook, Ch 12 (Attacking Users:
  Cross-Site Scripting)
- Bug Bounty Bootcamp, Ch 6 (XSS)
- XSS Cheat Sheet (PortSwigger)
- OWASP WSTG v4.2 (WSTG-INPV-01, WSTG-INPV-02)
- The Tangled Web, Ch 6, 9 (Output Encoding)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
