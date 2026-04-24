# gaps — xss-hunter

**Source:** Author notes on what the source methodology did NOT cover.

The source (`Guia Mestre de Vulnerabilidades XSS_ Detecção e Mitigação.md`)
covers Reflected and Stored XSS in depth. Coverage gaps to keep in mind:

---

## DOM XSS — Delegated, Not Covered Here

DOM XSS is explicitly out of scope for this skill — it has its own
`dom-xss-hunter` skill and source note. Any reflection whose source
is a client-side API (`location.hash`, `document.URL`, `postMessage`,
`window.name`, `document.referrer`) and whose sink is a JavaScript
function (`innerHTML`, `eval`, `document.write`, `setTimeout(str)`)
must be handed off to `dom-xss-hunter`.

## Trusted Types / Content Security Policy (CSP) Bypasses

The source does not cover CSP bypass research paths:
- `jsonp` endpoints as CSP-whitelisted script sources
- `nonce` replay via cached pages
- `strict-dynamic` bypass via script-tag injection whose nonce is forwarded
- AngularJS template-injection gadgets that bypass CSP

If the target has a strict CSP (`'strict-dynamic'` + nonce), successful
XSS injection may still not execute — report the injection as a finding
but note the effective-mitigation status.

## Template-Engine Boundary (handoff to `ssti-hunter`)

A reflection in a server-rendered template can be Template Injection
(server-side, RCE) instead of XSS. Probes like `{{7*7}}` or `${7*7}`
returning `49` indicate SSTI — delegate to `ssti-hunter`, do not
mis-classify as XSS.

## mXSS (Mutation XSS)

Browser HTML parsers normalize and re-serialize DOM trees, occasionally
turning benign HTML into executable HTML after it passes through a
sanitizer like `DOMPurify`. Classic gadget: `<noscript><p title="</noscript><img src onerror=alert(1)>">`.
The source does not cover mXSS research paths; include mXSS payloads
when the target uses client-side sanitization.

## XSS via PDF / SVG / MS Office Rendering

SVG `<script>` execution in an `<img>` vs `<object>` vs `<embed>` tag
differs per browser; PDF forms can execute JavaScript; DOCX preview
render in Office 365. The source does not cover file-upload XSS paths
beyond a brief mention of uploaded filenames.

## Subdomain Cookie Scoping

Reflected XSS on `app.target.com` can steal cookies scoped to
`.target.com`, hijacking `main.target.com` sessions. The methodology
treats XSS impact as same-origin; cross-subdomain impact should be
assessed explicitly.

## Framework-Specific Context Confusion

- React: `dangerouslySetInnerHTML`, `href={userUrl}` (javascript: URL)
- Vue: `v-html`, `:href="userUrl"` (javascript: URL)
- Angular: bypass of `DomSanitizer` via `bypassSecurityTrustHtml`

The source is framework-agnostic; these framework-specific XSS paths
should be checked on top of the generic methodology.

## AMP / Accelerated-Mobile-Pages Context

AMP has its own allowlist of elements and disallows arbitrary `<script>`.
XSS inside AMP content requires AMP-specific gadgets — not in scope for
the source.

## WebSocket / Server-Sent Events (SSE) Reflections

User input echoed through WebSocket frames or SSE streams and rendered
client-side is a valid XSS path not covered by the HTTP-focused source.
