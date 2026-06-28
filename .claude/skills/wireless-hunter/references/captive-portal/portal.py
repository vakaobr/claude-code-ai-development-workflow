#!/usr/bin/env python3
"""
Security-awareness captive portal for wireless-hunter workshops.

FLOW: splash (choose provider; shows a live "what this network sees about
you" table from client-side JS) -> SIMULATED, logo-branded provider login
page -> on submit, the awareness page reveals ONLY the first 4 characters
of the password typed, then DISCARDS the rest.

Privacy contract:
 - Full password is truncated to 4 chars; the rest is never stored/logged.
 - Device fingerprint is gathered + displayed CLIENT-SIDE only
   (fingerprint.js); it is NOT sent to or stored by the server.
 - The log holds only non-secret metadata: timestamp, client IP, provider,
   view|submit.
 - Login pages are LOCAL SIMULATIONS (not real providers, not a proxy).
   For the live AiTM demo against real providers see README.md (evilginx,
   consent-gated, test account only).

Run:  sudo PORT=80 python3 portal.py      # or PORT=8088 for a local test
"""
import os, html, json, http.server, socketserver, urllib.parse, urllib.request, datetime

PORT = int(os.environ.get("PORT", "80"))
HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(HERE, "submissions.log")
BRAND = "Free WiFi Gateway"

# Brand logos (inline SVG, offline-safe) for the simulated login brand bar.
LOGOS = {
 "account":   '<svg viewBox="0 0 24 24" width="20" height="20" fill="#fff"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7z"/></svg>',
 "google":    '<svg viewBox="0 0 48 48" width="20" height="20"><path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9 3.6l6.7-6.7C35.6 2.6 30.1 0 24 0 14.6 0 6.4 5.4 2.5 13.3l7.8 6.1C12.2 13.2 17.6 9.5 24 9.5z"/><path fill="#4285F4" d="M46.5 24.5c0-1.6-.1-3.1-.4-4.5H24v9h12.7c-.6 3-2.2 5.5-4.7 7.2l7.3 5.7C43.9 38 46.5 31.8 46.5 24.5z"/><path fill="#FBBC05" d="M10.3 28.6c-.5-1.5-.8-3-.8-4.6s.3-3.1.8-4.6l-7.8-6.1C.9 16.5 0 20.1 0 24s.9 7.5 2.5 10.7l7.8-6.1z"/><path fill="#34A853" d="M24 48c6.1 0 11.3-2 15-5.5l-7.3-5.7c-2 1.4-4.7 2.3-7.7 2.3-6.4 0-11.8-3.7-13.7-9l-7.8 6.1C6.4 42.6 14.6 48 24 48z"/></svg>',
 "microsoft": '<svg viewBox="0 0 23 23" width="18" height="18"><path fill="#F25022" d="M1 1h10v10H1z"/><path fill="#7FBA00" d="M12 1h10v10H12z"/><path fill="#00A4EF" d="M1 12h10v10H1z"/><path fill="#FFB900" d="M12 12h10v10H12z"/></svg>',
 "github":    '<svg viewBox="0 0 16 16" width="20" height="20" fill="#fff"><path d="M8 0C3.6 0 0 3.6 0 8c0 3.5 2.3 6.5 5.5 7.6.4.1.5-.2.5-.4v-1.3c-2.2.5-2.7-1-2.7-1-.4-.9-.9-1.2-.9-1.2-.7-.5.1-.5.1-.5.8.1 1.2.8 1.2.8.7 1.2 1.9.9 2.3.7.1-.5.3-.9.5-1.1-1.8-.2-3.6-.9-3.6-4 0-.9.3-1.6.8-2.1-.1-.2-.4-1 .1-2.1 0 0 .7-.2 2.2.8a7.5 7.5 0 014 0c1.5-1 2.2-.8 2.2-.8.5 1.1.2 1.9.1 2.1.5.5.8 1.2.8 2.1 0 3.1-1.8 3.8-3.6 4 .3.3.6.8.6 1.6v2.4c0 .2.1.5.6.4C13.7 14.5 16 11.5 16 8c0-4.4-3.6-8-8-8z"/></svg>',
 "email":     '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#fff" stroke-width="2"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/></svg>',
 "phone":     '<svg viewBox="0 0 24 24" width="18" height="18" fill="#fff"><path d="M6.6 10.8c1.4 2.8 3.8 5.2 6.6 6.6l2.2-2.2c.3-.3.7-.4 1-.2 1.1.4 2.3.6 3.6.6.6 0 1 .4 1 1V20c0 .6-.4 1-1 1C10.6 21 3 13.4 3 4c0-.6.4-1 1-1h3.5c.6 0 1 .4 1 1 0 1.2.2 2.4.6 3.6.1.3 0 .7-.2 1l-2.3 2.2z"/></svg>',
 "whatsapp":  '<svg viewBox="0 0 32 32" width="20" height="20"><path fill="#25D366" d="M16 0A16 16 0 002.3 24.2L0 32l8-2.1A16 16 0 1016 0z"/><path fill="#fff" d="M12 8c-.3-.7-.6-.7-.9-.7h-.8c-.3 0-.7.1-1 .5-.4.4-1.3 1.3-1.3 3.1s1.3 3.6 1.5 3.9c.2.3 2.6 4 6.4 5.6 3.2 1.3 3.8 1 4.5.9.7-.1 2.2-.9 2.5-1.7.3-.9.3-1.6.2-1.7-.1-.2-.4-.3-.8-.5s-2.2-1.1-2.5-1.2c-.3-.1-.6-.2-.8.2-.3.4-.9 1.2-1.1 1.4-.2.2-.4.3-.8.1-.4-.2-1.6-.6-3-1.9-1.1-1-1.9-2.2-2.1-2.6-.2-.4 0-.6.2-.8l.6-.7c.2-.3.2-.4.4-.7.1-.3 0-.5 0-.7s-.8-2.1-1.1-2.8z"/></svg>',
}
PROVIDERS = {
 "account":   {"name": "Account login", "accent": "#1ca0f2", "fg": "#fff",     "kind": "password"},
 "google":    {"name": "Google",        "accent": "#ffffff", "fg": "#3c4043", "kind": "password"},
 "microsoft": {"name": "Microsoft",     "accent": "#2f2f2f", "fg": "#fff",     "kind": "password"},
 "github":    {"name": "GitHub",        "accent": "#161b22", "fg": "#fff",     "kind": "password"},
 "email":     {"name": "Email address", "accent": "#1ca0f2", "fg": "#fff",     "kind": "contact", "field": "Email address"},
 "phone":     {"name": "Phone number",  "accent": "#1ca0f2", "fg": "#fff",     "kind": "contact", "field": "Phone number"},
 "whatsapp":  {"name": "WhatsApp",      "accent": "#25D366", "fg": "#fff",     "kind": "contact", "field": "WhatsApp number"},
}

def _geo_html():
    """Geolocate the portal host's PUBLIC IP (city, ISP, VPN/proxy flag).
    On a rogue AP this is the uplink, so it shows the venue location for all
    clients. Display-only; not stored. Needs internet; degrades gracefully."""
    try:
        url = "http://ip-api.com/json/?fields=status,country,regionName,city,isp,proxy,hosting,query"
        with urllib.request.urlopen(url, timeout=4) as r:
            d = json.load(r)
        if d.get("status") != "success":
            raise ValueError("lookup failed")
        loc = ", ".join(x for x in (d.get("city"), d.get("regionName"), d.get("country")) if x)
        vpn = "Yes" if (d.get("proxy") or d.get("hosting")) else "No"
        rows = [("Approx location", loc or "unknown"),
                ("ISP / carrier", d.get("isp") or "unknown"),
                ("VPN / proxy", vpn),
                ("Public IP", d.get("query") or "unknown")]
        body = "".join('<div class="geo-row"><span>%s</span><b>%s</b></div>'
                       % (html.escape(k), html.escape(str(v))) for k, v in rows)
        return '<div class="geo"><div class="geo-h">From your network address alone:</div>%s</div>' % body
    except Exception:
        return ('<div class="geo"><div class="geo-h">Location / ISP / VPN check</div>'
                '<div class="geo-row"><span>status</span><b>needs internet on the portal host '
                '(works on the live AP)</b></div></div>')

GEO_HTML = _geo_html()   # looked up once at startup (uplink IP is stable per venue)

def _read(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return f.read()

def log_event(ip, provider, kind):
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with open(LOG, "a") as f:
        f.write(f"{ts}\t{ip}\t{provider}\t{kind}\n")     # never any secret

def render_index(ip):
    return _read("index.html").replace("{{CLIENT_IP}}", html.escape(ip)).replace("{{GEO}}", GEO_HTML)

def render_login(provider):
    p = PROVIDERS[provider]
    if p["kind"] == "password":
        fields = ('<input class="inp" type="text" name="username" placeholder="Email or username" autofocus required>'
                  '<input class="inp" type="password" name="password" placeholder="Password" required>')
        btn = "Sign in"
    else:
        fields = f'<input class="inp" type="text" name="username" placeholder="{html.escape(p["field"])}" autofocus required>'
        btn = "Send code"
    return (_read("login.html")
            .replace("{{PROVIDER}}", provider).replace("{{NAME}}", html.escape(p["name"]))
            .replace("{{ACCENT}}", p["accent"]).replace("{{FG}}", p["fg"])
            .replace("{{LOGO}}", LOGOS.get(provider, "")).replace("{{BRAND}}", BRAND)
            .replace("{{FIELDS}}", fields).replace("{{BTN}}", btn))

def render_aware(ip, capture_html=""):
    return (_read("aware.html").replace("{{CAPTURE}}", capture_html)
            .replace("{{CLIENT_IP}}", html.escape(ip)).replace("{{GEO}}", GEO_HTML))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=HERE, **k)

    def _html(self, body, code=200):
        b = body.encode("utf-8")
        self.send_response(code); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def _redirect(self, loc):
        self.send_response(302); self.send_header("Location", loc); self.end_headers()

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        ip = self.client_address[0]
        if u.path in ("/generate_204", "/gen_204", "/hotspot-detect.html", "/ncsi.txt",
                      "/connecttest.txt", "/canonical.html", "/success.txt",
                      "/library/test/success.html"):
            return self._redirect("/")
        if u.path in ("/", "/index.html"):
            return self._html(render_index(ip))
        if u.path in ("/style.css", "/fingerprint.js"):
            return super().do_GET()
        if u.path == "/login":
            provider = (urllib.parse.parse_qs(u.query).get("provider", ["account"])[0]).lower()
            if provider not in PROVIDERS:
                return self._redirect("/")
            log_event(ip, provider, "view")
            return self._html(render_login(provider))
        if u.path == "/aware":
            return self._html(render_aware(ip, ""))
        return self._html(render_index(ip))

    def do_POST(self):
        ip = self.client_address[0]
        if urllib.parse.urlparse(self.path).path != "/submit":
            return self._redirect("/")
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n).decode("utf-8", "replace")
        form = urllib.parse.parse_qs(raw)
        provider = (form.get("provider", ["?"])[0]).lower()
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        prefix = password[:4]                       # keep first 4 only
        del raw, form, password                     # discard the rest immediately
        p = PROVIDERS.get(provider, {"name": provider, "kind": "password"})
        log_event(ip, provider, "submit")           # no secret logged
        u_safe = html.escape(username[:80])
        if p.get("kind") == "password":
            shown = html.escape(prefix) + ("…" if prefix else "")
            cap = (f'<div class="capture"><div class="cap-h">⚠ We just captured your {html.escape(p["name"])} login</div>'
                   f'<div class="cap-row">Username: <b>{u_safe or "(blank)"}</b></div>'
                   f'<div class="cap-row">Password starts with: <b>{shown or "(blank)"}</b> '
                   f'<span class="cap-note">(only the first 4 chars were kept to prove it - the rest was '
                   f'discarded, nothing stored)</span></div></div>')
        else:
            cap = (f'<div class="capture"><div class="cap-h">⚠ You just handed over your {html.escape(p["name"])}</div>'
                   f'<div class="cap-row"><b>{u_safe or "(blank)"}</b> '
                   f'<span class="cap-note"> - enough to target you with phishing / SIM-swap.</span></div></div>')
        return self._html(render_aware(ip, cap))

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    print(f"[*] {BRAND} captive portal on :{PORT}  (simulated logins, first-4 reveal, client-side fingerprint, no secrets stored)")
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
        httpd.serve_forever()
