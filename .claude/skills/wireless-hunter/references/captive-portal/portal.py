#!/usr/bin/env python3
"""
Security-awareness captive portal for wireless-hunter workshops.

SAFE BY DEFAULT: the social-login buttons go to the awareness ("gotcha")
page. They only redirect to evilginx lure URLs if you fill in LURES below
AND set LIVE_AITM=True -- which you do ONLY for a consented demo against a
SEEDED TEST ACCOUNT you control (never attendees' real accounts).

The portal itself NEVER sees or stores credentials. It logs only the FACT
that a provider button was clicked (timestamp + client IP + provider) so
you can show click-rates. evilginx (if enabled) is the component that
demonstrates session/MFA-token capture -- and that runs under the
social-engineering-hunter gates (se_consent_ref, se_evilginx) with token
destruction after proof.

Run:  sudo python3 portal.py        # port 80 needs root; or PORT=8080
"""
import os
import http.server
import socketserver
import urllib.parse
import datetime

PORT = int(os.environ.get("PORT", "80"))
HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(HERE, "submissions.log")

# --- DEMO MODE --------------------------------------------------------
# Leave LIVE_AITM = False for the safe awareness demo (buttons -> /aware).
# Set True ONLY with signed consent + a test account; fill the lure URLs
# from your evilginx instance (`lures get-url <id>`).
LIVE_AITM = os.environ.get("LIVE_AITM", "false").lower() == "true"
LURES = {
    "google":    os.environ.get("LURE_GOOGLE", ""),     # e.g. https://<evilginx-domain>/<lure>
    "microsoft": os.environ.get("LURE_MICROSOFT", ""),
    "github":    os.environ.get("LURE_GITHUB", ""),
}
# ----------------------------------------------------------------------

def log_click(ip, provider):
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with open(LOG, "a") as f:
        f.write(f"{ts}\t{ip}\t{provider}\n")

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=HERE, **k)

    def _send(self, path, code=200):
        try:
            with open(os.path.join(HERE, path), "rb") as f:
                body = f.read()
        except FileNotFoundError:
            self.send_error(404); return
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        # OS captive-portal probes -> force the splash to pop
        if u.path in ("/generate_204", "/gen_204", "/hotspot-detect.html",
                      "/ncsi.txt", "/connecttest.txt", "/canonical.html",
                      "/success.txt", "/library/test/success.html"):
            return self._redirect("/")
        if u.path in ("/", "/index.html"):
            return self._send("index.html")
        if u.path == "/style.css":
            return super().do_GET()
        if u.path == "/aware":
            return self._send("aware.html")
        if u.path == "/go":
            q = urllib.parse.parse_qs(u.query)
            provider = (q.get("provider", ["?"])[0]).lower()
            ip = self.client_address[0]
            log_click(ip, provider)
            lure = LURES.get(provider, "")
            if LIVE_AITM and lure:
                return self._redirect(lure)          # consented AiTM demo
            return self._redirect("/aware")          # safe default
        return self._send("index.html")

    def log_message(self, *a):  # quiet
        pass

if __name__ == "__main__":
    mode = "LIVE-AiTM (evilginx)" if LIVE_AITM else "SAFE (awareness only)"
    print(f"[*] Captive portal on :{PORT}  mode={mode}  log={LOG}")
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
        httpd.serve_forever()
