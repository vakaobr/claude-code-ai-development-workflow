---
name: clickjacking-hunter
description: "Tests sensitive state-changing pages for clickjacking / UI-redress weaknesses by auditing frame-protection headers, cookie attributes, and pre-fillable URL parameters. Use when a web app has destructive or account-modifying actions (password change, transfer, delete) that complete with a single click; when X-Frame-Options / CSP frame-ancestors are missing or permissive; or when the orchestrator needs to confirm whether a finding can be exploited without a secondary confirmation. Produces findings with CWE-1021 mapping, a local framing PoC, and developer-facing header/cookie remediation. Defensive testing only, against assets listed in .claude/security-scope.yaml."
model: sonnet
allowed-tools: Read, Grep, Glob, WebFetch(domain:*.in-scope-domain.com)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: client-side
  authorization_required: true
  tier: T2
  source_methodology: "Guia Completo de Segurança e Testes contra Clickjacking.md"
  service_affecting: false
  composed_from: []
---

# Clickjacking Hunter

## Goal

Audit the target application's clickjacking (UI redressing) defenses so the
team can prove that every sensitive state-changing action is protected against
being embedded in a third-party frame. This skill implements WSTG-CLNT-09 and
maps findings to CWE-1021 (Improper Restriction of Rendered UI Layers). The
goal is to hand the engineering team a concrete list of pages that lack
`X-Frame-Options`, `Content-Security-Policy: frame-ancestors`, or `SameSite`
cookie protection, with a copy-pasteable HTML PoC demonstrating framing and
header/cookie remediation snippets.

## When to Use

- The target exposes state-changing actions (update profile, change password,
  delete data, transfer funds) that complete with a single click.
- HTTP response headers lack `X-Frame-Options` or `Content-Security-Policy:
  frame-ancestors`, or use permissive values like `frame-ancestors *`.
- Session cookies do not set `SameSite=Lax` or `SameSite=Strict`.
- Sensitive actions accept GET parameters that pre-fill form state (e.g.,
  `?recipient=X&amount=Y`).
- JavaScript "frame-busting" code is the only defense, without server-side
  headers.
- User invokes via `/clickjacking-hunter` or the orchestrator selects this
  skill after attack-surface mapping identifies authenticated state-changing
  endpoints.

## When NOT to Use

- For automatic cross-site request attacks that do not require user UI
  interaction — use `csrf-hunter` instead.
- For script execution in a victim's browser — use `xss-hunter` or
  `dom-xss-hunter`.
- For pages whose functionality is intentionally embeddable (public widgets,
  share buttons, oEmbed resources).
- For unauthenticated pages with no session-bound sensitive actions.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active` or `passive`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or doesn't
   parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND the target's
   `testing_level` is `active` or `passive` (this skill is passive —
   framing tests run locally, the only live traffic is normal HTTP fetches).
3. If the target is ambiguous (not explicitly listed), write the ambiguity
   to `.claude/planning/{issue}/SCOPE_QUESTIONS.md` and halt on that target
   only. Continue other in-scope work.
4. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log before
   producing any probes.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name (e.g., `security-audit-q2-2026`)
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific page paths to focus on (e.g.,
  `/account/settings`, `/transfer`)
- `{user_a}`: an authenticated session for the target (framing needs a
  logged-in victim context to be exploitable)

If authenticated sensitive actions exist but no test session is provided,
halt and request credentials.

## Methodology

### Phase 1: Identify State-Changing Actions

1. **Inventory sensitive single-click actions** [Bug Bounty Bootcamp, Ch 8, p. 150]

   Do: Walk the authenticated app (or read the existing
   `.claude/planning/{issue}/API_INVENTORY.md` and any UI sitemap) and list
   every action that changes account state in one click: password change,
   email change, account deletion, fund transfer, role change, API key
   rotation, permission grants.

   Vulnerable response: A non-empty list of such actions.

   Not-vulnerable response: The app contains only informational pages or
   every sensitive action requires a multi-step confirmation (password
   re-entry, TOTP).

   Record: Write the action inventory to
   `.claude/planning/{issue}/clickjacking-targets.md`.

2. **Classify pre-fillable parameters** [Bug Bounty Bootcamp, Ch 8]

   Do: For each action, check whether its URL accepts GET parameters that
   initialize form state (e.g., `/transfer?recipient=X&amount=Y`). These
   actions are highest priority — the PoC doesn't require JavaScript to
   fill the form.

   Record: Mark pre-fillable actions in the target list with `prefillable:
   true`.

### Phase 2: Audit Frame-Protection Headers

3. **Check `X-Frame-Options` header** [Bug Bounty Bootcamp, Ch 8, p. 151]

   Do: For every sensitive action URL, fetch the page (as an authenticated
   user) and inspect the response headers.

   Vulnerable response: `X-Frame-Options` is missing, or set to `ALLOW-FROM
   {any cross-origin value}`, or present with an invalid value that browsers
   ignore.

   Not-vulnerable response: `X-Frame-Options: DENY` or `X-Frame-Options:
   SAMEORIGIN` is present.

   Record: Header matrix in `clickjacking-targets.md` per URL.

4. **Check `Content-Security-Policy: frame-ancestors`** [WSTG v4.2, 4.11.9]

   Do: For the same URLs, check `Content-Security-Policy` and specifically
   the `frame-ancestors` directive. Modern browsers prefer CSP over XFO when
   both are present.

   Vulnerable response: `frame-ancestors` is missing, or set to `*`, or
   includes untrusted origins.

   Not-vulnerable response: `frame-ancestors 'self'`, `'none'`, or a
   whitelist of known-trusted origins.

   Record: If XFO and CSP disagree (e.g., XFO=DENY but CSP=`frame-ancestors
   *`), note the inconsistency — modern browsers use CSP and the page is
   framable.

5. **Audit `SameSite` cookie attribute** [Bug Bounty Bootcamp, Ch 8, p. 151]

   Do: Inspect the `Set-Cookie` headers for the session cookie. Confirm
   `SameSite=Lax` or `SameSite=Strict`.

   Vulnerable response: `SameSite=None` with `Secure`, or `SameSite`
   unspecified (behavior is browser-dependent; older browsers send cookies
   on cross-site iframe requests).

   Not-vulnerable response: `SameSite=Lax` or `SameSite=Strict`.

   Record: Cookie matrix per domain.

### Phase 3: Confirm Framability

6. **Manual framing PoC** [WSTG v4.2, 4.11.9, p. 1083]

   Do: Create a local HTML file
   (`.claude/planning/{issue}/clickjacking-poc/frame-{n}.html`) that embeds
   the target page via `<iframe src="https://{target}/{path}">`. Open it in a
   browser while authenticated to the target.

   Vulnerable response: The target page renders inside the iframe.

   Not-vulnerable response: The browser blocks the frame (`refused to
   display... because it set 'X-Frame-Options' to 'DENY'`) or the page
   redirects/frame-busts out.

   Record: If the frame loads, append FINDING-NNN to SECURITY_AUDIT.md with
   the PoC HTML as evidence.

7. **Test JavaScript frame-busting bypass** [WSTG v4.2, 4.11.9, p. 353]

   Do: If framing is blocked by client-side JavaScript (e.g., `if (top !==
   self) top.location = self.location`), re-test using the `sandbox`
   attribute: `<iframe src="..." sandbox="allow-forms allow-scripts
   allow-same-origin">`. The `allow-top-navigation` exclusion disables the
   frame-busting redirect while keeping the page interactive.

   Vulnerable response: The page remains framed despite the frame-buster.

   Not-vulnerable response: The page still breaks out, or a server-side
   header (XFO/CSP) also blocks framing.

   Record: Any JS-only defense that the sandbox bypasses is itself a
   finding (weak defense).

### Phase 4: Exploit Feasibility

8. **Build transparent-overlay PoC for pre-fillable actions** [WSTG v4.2, 4.11.9, p. 1084]

   Do: For each framable action with `prefillable: true`, extend the PoC
   with a decoy button under the iframe's target button. Use CSS to set the
   iframe's opacity to a near-zero value (e.g., `opacity: 0.00001`) and
   position the decoy so that a user clicking the decoy actually clicks
   through to the target's action button.

   Vulnerable response: Clicking the decoy triggers the sensitive action on
   the framed page (verify by checking the target app's state afterward as
   the victim user).

   Not-vulnerable response: Click lands on the overlay, not the framed
   button — alignment across viewports is not guaranteed, which weakens
   impact.

   Record: Finding severity depends on which action was triggered — see
   severity rubric below.

9. **Audit pre-filled state initialization**
   [Bug Bounty Bootcamp, Ch 8, p. 154]

   Do: Confirm that the sensitive action can be fully parameterized via the
   URL. If the action requires the user to type a value (password, amount,
   recipient) that cannot be filled via query string, exploitation requires
   social engineering on top of the frame — lowers practical severity.

   Record: Note whether each finding requires user-typed input (Low impact)
   or is fully URL-driven (High impact).

## Payload Library

Framing probes are short HTML snippets, not payloads against the target —
there is no payload list worth a separate `references/payloads.md`. The
core probes inline in this skill are:

- **Basic frame probe**: `<iframe src="https://{target}/{path}"></iframe>`
- **Transparent overlay**: `#victim { opacity: 0.00001; z-index: 1; }`
  `#decoy { position: absolute; z-index: -1; }`
- **Sandbox bypass**: `<iframe src="..." sandbox="allow-forms allow-scripts
  allow-same-origin">`
- **Pre-filled URL**: `https://{target}/transfer?recipient=X&amount=Y`

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per the
schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-1021 (Improper Restriction of Rendered UI Layers or Frames).
  For findings that also bypass CSRF tokens via framing, add CWE-352.
- **OWASP**: WSTG-CLNT-09. For session-cookie contributions, also map to
  ASVS V3.4.
- **CVSS vectors**: typically `AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:N` — high
  attack complexity (requires viewport alignment and social engineering),
  user interaction required, integrity impact from the state change.
- **Evidence**: the response headers (with missing/weak XFO/CSP), the local
  HTML PoC file path, and a screenshot or description of the resulting
  application state change.
- **Remediation framing**: infra/platform engineer for the response-header
  layer, backend engineer for the cookie layer, product for
  confirmation-step UX changes. Include the three remediation layers in
  each finding.

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every finding distinguishes framable-but-inert actions from framable
      sensitive-state-change actions
- [ ] Every sensitive-state-change finding includes a local HTML PoC file
      and a description of the resulting state change
- [ ] Every finding includes a full remediation block (headers + cookie
      attribute + confirmation step)
- [ ] No finding was produced against an asset not in scope
- [ ] PoC HTML files live under `.claude/planning/{issue}/clickjacking-poc/`,
      not committed to the repo
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Inert framable pages**: The page is framable but the actions within it
  are non-sensitive (public news feed, dashboard view-only). Framability
  alone is not a vulnerability — it only matters for state-changing
  actions. Mark these as Informational or drop them.

- **Manual-input actions**: The target function requires the user to type
  sensitive data (password, recipient ID) into a field that cannot be
  pre-filled via URL parameters. Exploitation requires sophisticated social
  engineering and is generally Low impact.

- **Intentional embedding**: The resource is designed to be embedded as a
  widget, share button, or oEmbed resource. Confirm with the product team
  before filing — this is an intentional product design choice.

- **Non-production environments**: The vulnerability exists on a
  non-production environment that doesn't have access to live user
  sessions or real data. Drop unless there's a path to production.

## References

External:
- WSTG-CLNT-09: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking
- CWE-1021: https://cwe.mitre.org/data/definitions/1021.html
- OWASP Clickjacking Defense Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia Completo de Segurança e Testes contra Clickjacking.md`

Grounded in:
- Bug Bounty Bootcamp, Ch 8 (Clickjacking)
- The Web Application Hacker's Handbook, Ch 13 (Attacking Users)
- OWASP WSTG v4.2 (WSTG-CLNT-09)

Conversion date: 2026-04-23
Conversion prompt version: 1.0
