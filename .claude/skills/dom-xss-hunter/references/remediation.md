# remediation — dom-xss-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Completo de Testes e Mitigação de DOM XSS.md` (Section 8: REMEDIATION)

DOM XSS fixes are entirely client-side — the server's response doesn't
contain user-controlled data. The fix is to sanitize at the sink or
switch to a safe sink.

---

## 1. Use Safe Sinks

The single highest-impact rule: prefer `textContent` over `innerHTML`;
never interpolate strings into JS sinks.

### Safe vs unsafe DOM APIs

| Unsafe (HTML parser)                      | Safe (text)                                    |
|-------------------------------------------|------------------------------------------------|
| `el.innerHTML = str`                      | `el.textContent = str`                         |
| `el.outerHTML = str`                      | `el.replaceChildren(document.createTextNode(str))` |
| `el.insertAdjacentHTML(pos, str)`         | `el.insertAdjacentText(pos, str)`              |
| `document.write(str)`                     | `el.append(document.createTextNode(str))`      |
| `el.srcdoc = str`                         | Avoid entirely                                 |
| `el.setAttribute("on*", str)`             | `el.addEventListener("evt", handler)`          |
| `new Function(str)`                       | Named function + safe JSON parse               |
| `eval(str)`                               | **never**                                      |
| `setTimeout(str, n)`                      | `setTimeout(() => {...}, n)`                   |
| `setInterval(str, n)`                     | `setInterval(() => {...}, n)`                  |
| `location.href = "javascript:"+...`       | Validate URL scheme before assignment          |

---

## 2. Sanitize When HTML Is Genuinely Needed

When the feature requires user-supplied HTML (rich text editor, markdown
preview), use a robust sanitizer like DOMPurify:

```javascript
import DOMPurify from "dompurify";

const html = DOMPurify.sanitize(userInput, {
  ALLOWED_TAGS: ["b", "i", "em", "strong", "a", "p", "ul", "li"],
  ALLOWED_ATTR: ["href", "title"],
  ALLOWED_URI_REGEXP: /^https?:\/\//,
});
element.innerHTML = html;
```

Do NOT roll your own sanitizer with regex — it will be bypassed (mXSS).

---

## 3. Validate URLs Before Navigation

When assigning a source to `location.href`, `<a href>`, `window.open`:

```javascript
function isSafeURL(url) {
  try {
    const u = new URL(url, window.location.origin);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}

const href = new URLSearchParams(location.search).get("redirect");
if (isSafeURL(href)) {
  location.href = href;        // only http/https
}
```

Reject `javascript:`, `data:`, `vbscript:` schemes and relative URLs
that contain a scheme-like prefix.

---

## 4. Strict `postMessage` Origin Check

```javascript
window.addEventListener("message", (event) => {
  // 1. Verify the origin explicitly
  const ALLOWED_ORIGINS = ["https://trusted.example"];
  if (!ALLOWED_ORIGINS.includes(event.origin)) return;

  // 2. Validate the shape of event.data
  if (typeof event.data !== "object" || event.data === null) return;
  if (event.data.type !== "ui:update") return;
  if (typeof event.data.text !== "string" || event.data.text.length > 500) return;

  // 3. Use a safe sink
  document.getElementById("banner").textContent = event.data.text;
});
```

NEVER do `if (event.origin === "*")` — `*` is sender-only.

---

## 5. Content Security Policy (CSP)

CSP is a strong defence-in-depth layer. A strict CSP stops most DOM XSS
from executing even if the injection succeeds.

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-RANDOM_NONCE' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  frame-ancestors 'self';
  require-trusted-types-for 'script';
```

Key points:
- `'strict-dynamic'` trusts script elements that have a nonce, which
  blocks injected `<script>` tags that lack the nonce.
- `base-uri 'none'` prevents `<base href>` hijack.
- `require-trusted-types-for 'script'` enforces Trusted Types (next
  section).

---

## 6. Trusted Types (Chrome / Edge)

Turn dangerous-sink usage into a compile error at runtime:

```html
<!doctype html>
<meta http-equiv="Content-Security-Policy" content="require-trusted-types-for 'script'; trusted-types myPolicy;">
```

```javascript
const policy = trustedTypes.createPolicy("myPolicy", {
  createHTML: (input) => DOMPurify.sanitize(input),
});

element.innerHTML = policy.createHTML(userInput);
```

Once Trusted Types is enforced, `element.innerHTML = "<script>..."` (a
raw string) throws — the app MUST go through the policy.

---

## 7. Remove Dangerous Patterns from Dependencies

Run automated scans in CI:

```bash
# Semgrep for DOM XSS patterns
semgrep --config=p/xss ./src

# ESLint with security plugin
eslint --plugin=security --rule "security/detect-non-literal-require: error" src/
eslint --plugin=no-unsanitized --rule "no-unsanitized/method: error" src/

# RetireJS — stale library scanner
retire --path src/
```

`eslint-plugin-no-unsanitized` catches `el.innerHTML = ...` patterns at
lint time.

---

## 8. Defensive Patterns per Framework

### React

React escapes strings inserted via `{expr}` by default. The one path to
DOM XSS is `dangerouslySetInnerHTML`.

```jsx
// WRONG
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// RIGHT
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />

// BEST — avoid dangerouslySetInnerHTML entirely
<div>{userInput}</div>
```

Also: never do `href={userUrl}` without URL validation; `javascript:`
URLs still work.

### Vue 3

```vue
<!-- WRONG — v-html is the only path to DOM XSS in Vue -->
<div v-html="userInput"></div>

<!-- RIGHT — use {{ }} interpolation -->
<div>{{ userInput }}</div>

<!-- If HTML is needed: -->
<div v-html="DOMPurify.sanitize(userInput)"></div>
```

### Angular 2+

Angular escapes by default via its template engine. The pitfalls:

```typescript
// WRONG — bypassSecurityTrust* disables sanitization
this.sanitizer.bypassSecurityTrustHtml(userInput);
this.sanitizer.bypassSecurityTrustUrl(userInput);

// RIGHT — let Angular sanitize
// Use [innerHTML]="userInput" without bypass; Angular will strip scripts.
```

### jQuery

jQuery's `.html(str)` is `innerHTML`. Use `.text(str)`:

```javascript
// WRONG
$("#banner").html(userInput);

// RIGHT
$("#banner").text(userInput);
```

---

## 9. Block `javascript:` URLs in User-Provided Links

A separate function for URL-assignment sinks:

```javascript
function assignUserURL(el, rawUrl) {
  if (typeof rawUrl !== "string") return;
  const trimmed = rawUrl.trim();
  if (/^\s*(javascript|data|vbscript|file):/i.test(trimmed)) return;
  try {
    el.href = new URL(trimmed, window.location.origin).toString();
  } catch { /* invalid URL, do nothing */ }
}
```

---

## Framework Quick-Reference

| Framework   | Safe-sink API                                                                          |
|-------------|----------------------------------------------------------------------------------------|
| React       | `{text}`; `dangerouslySetInnerHTML` + DOMPurify; URL allowlist for `href`             |
| Vue 3       | `{{ text }}`; `v-html` + DOMPurify; `:href="safeUrl(userUrl)"`                         |
| Angular     | Default sanitization; never `bypassSecurityTrustHtml`; keep `DomSanitizer` defaults    |
| Svelte      | `{text}`; use `{@html}` only with DOMPurify                                            |
| Vanilla JS  | `textContent`, `createElement` + `setAttribute`; never `innerHTML`                     |
| jQuery      | `.text(...)`; `.attr("href", safeUrl(...))`                                            |

---

## 10. Regression Tests

```javascript
// playwright / cypress / jest-dom
test("hash fragment does not execute", async ({ page }) => {
  await page.goto("https://target/search#<img src=x onerror=window.__xss__=true>");
  await page.waitForLoadState("networkidle");
  const pwned = await page.evaluate(() => window.__xss__);
  expect(pwned).toBeUndefined();
});

test("postMessage from untrusted origin rejected", async ({ page }) => {
  await page.goto("https://target/");
  await page.evaluate(() => {
    window.postMessage("<img src=x onerror=window.__xss__=true>", "*");
  });
  const pwned = await page.evaluate(() => window.__xss__);
  expect(pwned).toBeUndefined();
});
```
