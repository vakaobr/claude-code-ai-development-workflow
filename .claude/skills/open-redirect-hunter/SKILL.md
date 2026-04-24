---
name: open-redirect-hunter
description: "Tests URL-redirect parameters for arbitrary-destination redirects via simple external URLs, protocol-relative bypasses (`//attacker`), path-prefix tricks (`/https://attacker`), userinfo confusion (`target@attacker`), fragment/encoding bypasses, Referer-based redirects, and `javascript:` pseudo-protocol in href sinks. Use when parameters named `url`, `redirect`, `next`, `return`, `destination`, `goto`, `rUrl`, `cancelUrl` appear in the inventory; when login / logout / deep-link flows accept user-supplied redirect targets; or when chained with OAuth (`oauth-oidc-hunter`). Produces findings with CWE-601 mapping, redirect-chain evidence, and allowlist + user-warning remediation. Defensive testing only, against assets listed in .claude/security-scope.yaml."
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
  tier: T2
  source_methodology: "Guia Técnico de Redirecionamento Aberto_ Auditoria e Mitigação.md"
  service_affecting: false
  composed_from: []
---

# Open Redirect Hunter

## Goal

Test URL-redirect parameters for arbitrary-destination redirects —
the flaw that lets an attacker craft a link on the legitimate
domain that silently forwards the victim to an attacker-controlled
site, enabling phishing and lending the target's domain
credibility to the attack. Also tests the chained scenario where
an open redirect leaks OAuth / SSO tokens. This skill implements
WSTG-CLNT-04 and maps findings to CWE-601 (URL Redirection to
Untrusted Site / Open Redirect). The goal is to give the team a
concrete list of redirect-parameter flaws with chain evidence
(especially when paired with OAuth) and allowlist + user-warning
remediation.

## When to Use

- Parameters named `url`, `redirect`, `redirect_url`, `next`,
  `return`, `returnTo`, `destination`, `goto`, `rUrl`,
  `cancelUrl`, `forward`, `successUrl` appear in inventory.
- Login / logout / deep-link flows accept user-supplied post-
  action destinations.
- API documentation mentions "redirect" for auth endpoints.
- `oauth-oidc-hunter` needs a chain target (open-redirect on an
  approved subdomain to leak OAuth tokens).
- The orchestrator selects this skill after `api-recon` surfaces
  redirect parameters via Arjun.

## When NOT to Use

- For XSS via `javascript:` pseudo-protocol reflections — use
  `xss-hunter` (though this skill dispatches here for the URL
  sink case).
- For SSRF (attacker controls what the SERVER fetches, not where
  the USER is redirected) — use `ssrf-hunter`.
- For OAuth redirect-URI-specific bypasses — use
  `oauth-oidc-hunter`; this skill identifies the open-redirect
  primitive, oauth-oidc-hunter leverages it for token leak.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist
   or doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND
   its `testing_level` is `active`.
3. Redirect tests aim at an EXTERNAL callback host. This host
   MUST be in the scope's `oob_listener` or
   `oauth_test_callback` allowlist. NEVER redirect to arbitrary
   public domains like `google.com` or `webhook.site` — even
   though benign, it shows up in logs and may trigger analyst
   alerts.
4. Do NOT actually deliver the redirect URL to real users. PoCs
   stay in the tester's browser.
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
   with status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific redirect-accepting
  endpoints
- `{user_a}`: optional — authenticated session (some redirects
  trigger only on authenticated flows)
- `{oauth_callback_host}`: authorized callback-listener host from
  scope

## Methodology

### Phase 1: Inventory Redirect Parameters

1. **Extract candidates from inventory**
   [Bug Bounty Bootcamp, Ch 7, p. 133]

   Do: From `ATTACK_SURFACE.md` / `API_INVENTORY.md`, filter:
   - URL query parameters matching the names:
     `url|redirect|redirect_url|next|return|returnTo|dest|destination|goto|rUrl|cancelUrl|forward|successUrl|continue|ref`
   - Form fields with same names
   - POST body parameters with URL-shaped values

   Also run `arjun -u https://{target}/{path} -w common-redirect-params.txt`
   for discovery.

   Record: `.claude/planning/{issue}/redirect-targets.md`.

### Phase 2: Simple External Redirect

2. **Direct external URL probe** [WAHH, Ch 13, p. 543]

   Do: For each candidate parameter, replace its value with the
   authorized callback host:
   ```
   ?redirect=https://{oauth_callback_host}/
   ?next=https://{oauth_callback_host}/open-redirect-poc
   ```

   Observe:
   - Response status (302 / 301 / 303 / 307 / 308 redirects)
   - `Location` header contents
   - Whether the browser follows the redirect to the callback
     host (manual test or scripted follow)

   Vulnerable response: `Location: https://{oauth_callback_host}/...`
   returned — any HTTP client following the redirect lands on the
   attacker host.

   Not-vulnerable response: "Invalid URL" error, 400 status, or
   redirect to a safe default.

   Record: FINDING-NNN per vulnerable parameter.

### Phase 3: Encoding / Parser-Confusion Bypasses

3. **Protocol-relative URL**
   [Bug Bounty Bootcamp, Ch 7, p. 136]

   Do: If simple external URL is filtered (e.g., server rejects
   `https://`), try protocol-relative variants:
   ```
   //{oauth_callback_host}/
   ////{oauth_callback_host}/
   ```

   These preserve the current scheme (HTTPS on production) but
   change the host.

4. **Path-prefix trick** [Bug Bounty Bootcamp, Ch 7, p. 136]

   Do: Some servers check that the redirect starts with `/` (to
   keep it same-origin) but don't validate further. Try:
   ```
   /https://{oauth_callback_host}/
   /\/{oauth_callback_host}/
   /%2F%2F{oauth_callback_host}/
   /%5c{oauth_callback_host}/
   ```

   The backslash variant tricks Windows-ish parsers; the
   URL-encoded variants trick decoders that run after the
   starts-with check.

5. **Userinfo / credential format** [Bug Bounty Bootcamp, Ch 7, p. 137]

   Do: Use the URL's userinfo syntax:
   ```
   https://{target}@{oauth_callback_host}/
   https://{target}.{oauth_callback_host}/
   ```

   The first form uses HTTP Basic-Auth-style userinfo; browsers
   ignore everything before `@` but naive validators see
   `{target}` as the host.

6. **Fragment and query confusion**
   [Bug Bounty Bootcamp, Ch 7, p. 137]

   Do: Exploit how parsers handle `#` and `?`:
   ```
   https://{oauth_callback_host}#{target}
   https://{oauth_callback_host}?{target}
   https://{oauth_callback_host}/?q={target}
   ```

   Some validators see `{target}` and approve; the actual host is
   `{oauth_callback_host}`.

7. **URL-encoding and double-encoding**
   [Bug Bounty Bootcamp, Ch 7, p. 138]

   Do: Test:
   ```
   %2f%2f{oauth_callback_host}
   %252f%252f{oauth_callback_host}
   %5c%5c{oauth_callback_host}
   ```

   Server-side URL-decoding that runs AFTER the allowlist check
   is the classic pattern.

### Phase 4: Referer-Based Redirects

8. **Referer-header redirect probe**
   [Bug Bounty Bootcamp, Ch 7, p. 135]

   Do: For pages like `/login` that redirect to "the previous
   page" based on Referer, craft a request with Referer set to
   the callback host:
   ```bash
   curl -i -H "Referer: https://{oauth_callback_host}/" \
     https://{target}/login
   ```

   Vulnerable response: Login success redirects to
   `{oauth_callback_host}`.

   Not-vulnerable response: App validates Referer is same-origin
   or a trusted list.

### Phase 5: Client-Side Redirects

9. **Fragment-based client-side redirect**
   [WSTG v4.2, OTG-CLIENT-04]

   Do: Check for client-side code that reads the URL fragment or
   a parameter and calls `window.location = ...`. Fragments
   don't reach the server, so only client-side redirects honor
   them. Test:
   ```
   https://{target}/#redirect=https://{oauth_callback_host}/
   https://{target}/page?next=https://{oauth_callback_host}/
   ```

   Observe in browser whether the page's JavaScript redirects.

   Vulnerable response: Client-side redirect executes.

   Cross-reference `dom-xss-hunter` — client-side URL sinks are
   shared surface.

10. **`javascript:` pseudo-protocol probe** [WAHH, Ch 13, p. 546]

    Do: For redirect parameters reflected into a link's `href`
    attribute (as opposed to server-side Location header), test:
    ```
    javascript:alert(document.domain)
    ```

    Vulnerable response: Link's `href` becomes the payload;
    clicking it executes JS in the target's origin. This is XSS,
    not just open redirect — file with cross-reference to
    `xss-hunter`.

### Phase 6: Chain for Impact (High-Value)

11. **OAuth token-leak chain** [zseano's methodology, p. 1091]

    Do: If the target supports OAuth AND this skill found an
    open redirect on an OAuth-approved subdomain, build a chain:

    ```
    https://{oauth-provider}/authorize?
      client_id={target_client}&
      redirect_uri=https://{approved-subdomain}/open-redirect-path?redirect=https://{oauth_callback_host}/&
      response_type=code&state=test
    ```

    The OAuth flow completes to the approved subdomain; the
    open redirect forwards the callback (with the `code`) to the
    attacker host.

    Vulnerable response: Callback host receives the leaked
    authorization code.

    Record: Chained finding — primary vuln is open redirect,
    leverage is OAuth token theft. Cross-reference
    `oauth-oidc-hunter`.

## Payload Library

Categories:

- **Direct external**: `https://{oauth_callback_host}/`
- **Protocol-relative**: `//{host}/`, `////{host}/`
- **Path-prefix tricks**: `/https://{host}/`, `/%2F%2F{host}/`,
  `/%5c{host}/`
- **Userinfo confusion**: `https://{target}@{host}/`
- **Fragment / query**: `https://{host}#{target}`,
  `https://{host}?{target}`
- **URL encoding**: `%2f%2f`, `%252f%252f`, `%5c%5c`
- **Referer-based**: set `Referer` header
- **Client-side fragment**: `#redirect=...`
- **`javascript:` pseudo-protocol**: for href-sink cases

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-601 (URL Redirection to Untrusted Site — "Open
  Redirect"). For `javascript:` cases that become XSS, add
  CWE-79.
- **OWASP**: WSTG-CLNT-04. For APIs, API8:2023 (Security
  Misconfiguration). For chained OAuth, also A07:2021
  (Identification and Authentication Failures).
- **CVSS vectors**: simple open redirect (phishing aid) —
  `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N`. Chained OAuth token
  leak — `...UI:R/S:C/C:H/I:H/A:N` (severity rises because the
  chain enables account takeover).
- **Evidence**: the request with the malicious parameter, the
  response showing `Location` header with the attacker host,
  and for client-side cases, a DevTools screenshot of the
  final-navigation state.
- **Remediation framing**: backend engineer. Include:
  - Strict allowlist of destination domains (exact match)
  - ID-mapping pattern: replace URL params with a server-side
    lookup key (`?dest=1` resolves to a fixed URL server-side)
  - Intermediate warning page: "You are leaving {site}. Continue
    to {destination}? [Confirm]" — defeats passive redirection
  - Referer validation: match against `{target}`'s own origin
  - `javascript:` / `data:` / `vbscript:` protocol blocking
  - Never trust URL-encoded input without decoding before
    allowlist check

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
- `.claude/planning/{issue}/oauth-chain-candidates.md` — lists
  open-redirects on approved OAuth subdomains for
  `oauth-oidc-hunter` Phase 2 step 5

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every finding includes the full request (with the
      malicious parameter value) and the response showing the
      `Location` header
- [ ] Client-side findings include DevTools evidence of the
      navigation happening
- [ ] Chain findings (OAuth) include the full flow capture,
      not just the open-redirect primitive
- [ ] All tests used the authorized `{oauth_callback_host}`;
      no arbitrary public domains
- [ ] `javascript:` pseudo-protocol findings cross-reference
      `xss-hunter`
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Safe reflection without redirect**: The parameter value is
  echoed in the response body (e.g., on a confirmation page)
  but the server never sends `Location`. Not an open redirect —
  but may be XSS if it reflects unescaped. Cross-reference
  `xss-hunter`.

- **Intentional external redirects**: Some features legitimately
  redirect externally (exit-page warning, external link click-
  through, share-to-social-media). If the feature requires user
  consent ("are you sure you want to leave?"), it's not an open
  redirect — it's consent-gated redirection.

- **Inert fragments**: A URL parameter contains a redirect-looking
  value but the client-side code never reads it for navigation.
  Reflection alone isn't a finding; confirm the parameter is
  actually processed.

- **Referer-based that requires Referer spoofing in the victim's
  browser**: An attacker needs to make the victim's browser send
  a crafted Referer. This is non-trivial (usually requires a
  cross-origin navigation from the attacker-controlled site). The
  redirect is still a finding but lower severity.

- **Allowlisted subdomain the attacker can claim**: If the target
  allowlists `*.{target}` for redirects AND there's a dangling
  subdomain (cross-reference `subdomain-takeover-hunter`), the
  attacker can take over a subdomain and then leverage the
  allowlist. File as chained finding.

- **Meta-refresh redirect without JavaScript**: HTML
  `<meta http-equiv="refresh" content="0;url=...">` can also be
  a redirect sink. Often missed by server-side filters that only
  check `Location` headers.

## References

External:
- WSTG-CLNT-04: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect
- CWE-601: https://cwe.mitre.org/data/definitions/601.html
- OWASP Unvalidated Redirects and Forwards Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia Técnico de Redirecionamento Aberto_ Auditoria e Mitigação.md`

Grounded in:
- Bug Bounty Bootcamp, Ch 7 (Open Redirect)
- The Web Application Hacker's Handbook, Ch 13 (Attacking Users)
- OWASP WSTG v4.2 (WSTG-CLNT-04, OTG-CLIENT-04)
- zseano's methodology (Chain with OAuth)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
