#!/usr/bin/env python3
"""Normalize web-check raw JSON into the assessment's recon artifacts.

Reads a directory of {check}.json files (produced by run-webcheck.sh) and
writes, under --out:

  WEBCHECK.md                     full structured snapshot (every check)
  PASSIVE_RECON.patch.md          append-ready blocks for web-recon-passive
  webcheck/findings-candidates.md proposed hygiene findings (Suspected)

Dependency-free (stdlib only). Defensive parsing: web-check's per-check
shapes vary, so every accessor tolerates missing/renamed fields and falls
back to a compact JSON excerpt rather than crashing.

This script NEVER appends to SECURITY_AUDIT.md — that is the skill's job
(it holds the audit lock and assigns monotonic IDs after human triage).
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone


def load(raw_dir, check):
    """Return parsed JSON for a check, or None if missing/errored/unparseable."""
    path = os.path.join(raw_dir, f"{check}.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None


def errored(raw_dir, check):
    return os.path.isfile(os.path.join(raw_dir, f"{check}.error.txt"))


def excerpt(obj, limit=1200):
    """Compact, length-bounded JSON for the snapshot."""
    try:
        s = json.dumps(obj, indent=2, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        s = str(obj)
    return s if len(s) <= limit else s[:limit] + "\n... (truncated)"


def g(obj, *keys, default=None):
    """Nested .get over dicts; returns default on any miss."""
    cur = obj
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur


def is_empty(obj):
    return obj is None or obj == {} or obj == [] or obj == ""


# ---------------------------------------------------------------------------
# Finding candidates. Each rule inspects one or more checks and may emit a
# (severity, cwe, owasp, title, detail, refer_to) tuple. All are SUSPECTED.
# Severity here is a *recon hygiene* hint; the analyst/hunter sets the real one.
# ---------------------------------------------------------------------------
def build_candidates(data):
    out = []

    def add(sev, cwe, owasp, title, detail, refer_to):
        out.append(dict(sev=sev, cwe=cwe, owasp=owasp, title=title,
                        detail=detail, refer_to=refer_to))

    # --- TLS / certificate (the only checks allowed to stand alone) ---
    ssl = data.get("ssl") or data.get("tls-connection")
    if isinstance(ssl, dict):
        # valid_to / valid_from naming varies across web-check versions
        valid_to = ssl.get("valid_to") or ssl.get("validTo") or g(ssl, "expires")
        if valid_to:
            add("Medium", "CWE-295", "WSTG-CRYP-01",
                "TLS certificate validity window should be verified",
                f"Certificate `valid_to` reported as `{valid_to}`. Confirm it is "
                "neither expired nor self-signed for a production flow.",
                "crypto-flaw-hunter")
        protocols = ssl.get("protocols") or ssl.get("protocol")
        if protocols:
            bad = [p for p in (protocols if isinstance(protocols, list) else [protocols])
                   if isinstance(p, str) and any(x in p for x in ("1.0", "1.1", "SSLv", "SSL 3"))]
            if bad:
                add("Medium", "CWE-327", "WSTG-CRYP-01",
                    "Deprecated TLS/SSL protocol appears enabled",
                    f"Handshake/report references deprecated protocol(s): {bad}.",
                    "crypto-flaw-hunter")

    # --- HSTS ---
    hsts = data.get("hsts")
    if isinstance(hsts, dict):
        compatible = hsts.get("compatible")
        message = hsts.get("message", "")
        if compatible is False or (isinstance(message, str) and "not" in message.lower()):
            add("Low", "CWE-319", "WSTG-CONF-07",
                "HTTP Strict Transport Security not enforced",
                f"HSTS check: {message or 'site not HSTS-compatible'}.",
                "crypto-flaw-hunter")

    # --- Security headers ---
    hsec = data.get("http-security")
    if isinstance(hsec, dict):
        header_map = {
            "contentSecurityPolicy": ("CWE-693", "Content-Security-Policy", "dom-xss-hunter / xss-hunter"),
            "xFrameOptions":         ("CWE-1021", "X-Frame-Options", "clickjacking-hunter"),
            "xContentTypeOptions":   ("CWE-693", "X-Content-Type-Options", None),
            "strictTransportPolicy": ("CWE-319", "Strict-Transport-Security", "crypto-flaw-hunter"),
            "referrerPolicy":        ("CWE-200", "Referrer-Policy", None),
        }
        for key, (cwe, label, refer) in header_map.items():
            if key in hsec and not hsec.get(key):
                add("Informational", cwe, "WSTG-CONF-07",
                    f"Security header missing: {label}",
                    f"`http-security` reports `{label}` not set.", refer)

    # --- Cookies ---
    cookies = data.get("cookies")
    cookie_list = None
    if isinstance(cookies, dict):
        cookie_list = cookies.get("cookies") or cookies.get("headerCookies")
    if isinstance(cookie_list, list):
        for c in cookie_list:
            if not isinstance(c, dict):
                continue
            name = c.get("name", "cookie")
            missing = [f for f in ("secure", "httpOnly") if not c.get(f)]
            if not c.get("sameSite"):
                missing.append("sameSite")
            if missing:
                add("Informational", "CWE-1004", "WSTG-SESS-02",
                    f"Cookie `{name}` missing attribute(s): {', '.join(missing)}",
                    "Session/auth cookies should set Secure, HttpOnly, and SameSite.",
                    "session-flaw-hunter / csrf-hunter")

    # --- DNSSEC ---
    dnssec = data.get("dnssec")
    if isinstance(dnssec, dict):
        # web-check reports per-record-type dicts with isFound flags
        any_found = json.dumps(dnssec).lower().count('"isfound": true') > 0
        if not any_found:
            add("Informational", "CWE-350", "WSTG-CONF-noinfo",
                "DNSSEC does not appear to be enabled",
                "No DNSSEC records detected; domain is more exposed to DNS spoofing.",
                None)

    # --- Mail config (SPF / DMARC / DKIM) ---
    mail = data.get("mail-config")
    if isinstance(mail, dict):
        blob = json.dumps(mail).lower()
        for mech, cwe in (("spf", "CWE-noinfo"), ("dmarc", "CWE-noinfo")):
            if mech not in blob:
                add("Informational", cwe, "WSTG-CONF-noinfo",
                    f"Email anti-spoofing record missing: {mech.upper()}",
                    f"No {mech.upper()} policy observed in mail configuration; "
                    "domain may be spoofable in phishing.", None)

    # --- security.txt ---
    stxt = data.get("security-txt")
    if isinstance(stxt, dict) and stxt.get("isPresent") is False:
        add("Informational", "CWE-noinfo", "RFC-9116",
            "No /.well-known/security.txt published",
            "Best-practice vulnerability-disclosure contact file is absent.", None)

    # --- Reputation / threats / blocklists ---
    for chk, label in (("threats", "threat-intel"), ("block-lists", "blocklist")):
        v = data.get(chk)
        if isinstance(v, dict) and json.dumps(v).lower().count('"isspam": true') + \
           json.dumps(v).lower().count('"blacklisted": true') > 0:
            add("Low", "CWE-noinfo", "—",
                f"Host appears on a {label}",
                f"`{chk}` returned at least one positive reputation hit; verify "
                "whether it reflects the asset or a shared IP.", None)

    # --- Open ports beyond 80/443 (active tier only) ---
    ports = data.get("ports")
    if isinstance(ports, dict):
        open_ports = ports.get("openPorts") or ports.get("open") or []
        if isinstance(open_ports, list):
            extra = [p for p in open_ports if p not in (80, 443, "80", "443")]
            if extra:
                add("Informational", "CWE-200", "WSTG-INFO-noinfo",
                    f"Ports open beyond 80/443: {extra}",
                    "Additional exposed services widen the attack surface; confirm each is intended.",
                    "web-recon-active")

    return out


# ---------------------------------------------------------------------------
# Snapshot rendering
# ---------------------------------------------------------------------------
SECTION_ORDER = [
    ("Network / IP", ["get-ip", "location", "trace-route"]),
    ("DNS", ["dns", "dns-server", "dnssec", "txt-records", "mail-config"]),
    ("TLS / Certificate", ["ssl", "tls-connection", "tls-labs", "hsts"]),
    ("HTTP Posture", ["status", "headers", "http-security", "cookies", "redirects", "firewall"]),
    ("Technology", ["tech-stack", "social-tags", "carbon", "quality"]),
    ("Surface", ["subdomains", "ports", "linked-pages", "sitemap", "robots-txt", "security-txt"]),
    ("Reputation / OSINT", ["threats", "block-lists", "shodan", "rank", "whois", "archives", "screenshot"]),
]


def render_snapshot(target, data, raw_dir, ran_checks):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# web-check Recon Snapshot: {target}",
        "",
        f"**Generated:** {now}  ",
        f"**Source:** self-hosted lissy93/web-check  ",
        f"**Checks captured:** {len(ran_checks)}  ",
        "",
        "> Enumeration data, not confirmed findings. Hygiene gaps are proposed",
        "> in `webcheck/findings-candidates.md` for analyst triage.",
        "",
    ]
    for title, checks in SECTION_ORDER:
        present = [c for c in checks if c in data or errored(raw_dir, c)]
        if not present:
            continue
        lines.append(f"## {title}")
        lines.append("")
        for c in present:
            if errored(raw_dir, c):
                lines += [f"### {c}", "", "_check errored (see raw/{}.error.txt)_".format(c), ""]
                continue
            obj = data[c]
            if is_empty(obj):
                lines += [f"### {c}", "", "_empty — no data (often a missing API key)_", ""]
                continue
            lines += [f"### {c}", "", "```json", excerpt(obj), "```", ""]
    return "\n".join(lines) + "\n"


def render_passive_patch(target, data):
    """Append-ready blocks mapped onto web-recon-passive's dossier sections."""
    lines = [
        f"# PASSIVE_RECON patch — from web-check ({target})",
        "",
        "Merge these into PASSIVE_RECON.md (append + de-duplicate; do not clobber).",
        "",
    ]

    # Subdomains
    subs = data.get("subdomains")
    sub_names = []
    if isinstance(subs, dict):
        items = subs.get("subdomains") or subs.get("domains") or []
        for it in items if isinstance(items, list) else []:
            if isinstance(it, dict):
                sub_names.append(it.get("subdomain") or it.get("name") or it.get("domain"))
            elif isinstance(it, str):
                sub_names.append(it)
    sub_names = sorted({s for s in sub_names if s})
    lines += ["## Subdomains (web-check)", ""]
    lines += ([f"- {s}" for s in sub_names] or ["_none returned (SecurityTrails key may be unset)_"])
    lines += [""]

    # Tech fingerprint
    lines += ["## Tech Fingerprint (web-check)", ""]
    server = g(data, "headers", "server") or g(data, "headers", "Server")
    powered = g(data, "headers", "x-powered-by") or g(data, "headers", "X-Powered-By")
    if server:
        lines.append(f"- Server: `{server}`")
    if powered:
        lines.append(f"- X-Powered-By: `{powered}`")
    tech = data.get("tech-stack")
    techs = []
    if isinstance(tech, dict):
        t = tech.get("technologies") or tech.get("results") or []
        for it in t if isinstance(t, list) else []:
            if isinstance(it, dict):
                techs.append(it.get("name"))
            elif isinstance(it, str):
                techs.append(it)
    techs = sorted({x for x in techs if x})
    if techs:
        lines.append(f"- Technologies: {', '.join(techs)}")
    if not (server or powered or techs):
        lines.append("_no fingerprint data captured_")
    lines += [""]

    # Metafiles
    lines += ["## Metafiles (web-check)", ""]
    for c, label in (("robots-txt", "robots.txt"), ("sitemap", "sitemap.xml"),
                     ("security-txt", ".well-known/security.txt")):
        v = data.get(c)
        if isinstance(v, dict) and "isPresent" in v:
            present = "present" if v.get("isPresent") else "absent"
        elif isinstance(v, dict) and not is_empty(v):
            present = "present"
        else:
            present = "absent/empty"
        lines.append(f"- {label}: {present}")
    lines += [""]
    return "\n".join(lines) + "\n"


def render_candidates(target, candidates):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# web-check candidate findings: {target}",
        "",
        f"**Generated:** {now}",
        "",
        "All entries are **Suspected** recon-hygiene candidates. The analyst",
        "promotes only self-standing recon facts into SECURITY_AUDIT.md (with",
        "the audit lock + monotonic IDs); the rest go to the named hunter.",
        "",
        f"**Candidate count:** {len(candidates)}",
        "",
    ]
    order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
    for i, c in enumerate(sorted(candidates, key=lambda x: order.get(x["sev"], 9)), 1):
        refer = f"  \n**Refer to:** {c['refer_to']}" if c["refer_to"] else ""
        lines += [
            f"## CANDIDATE-{i:03d} — {c['title']}",
            "",
            f"**Severity (hint):** {c['sev']}  \n"
            f"**CWE:** {c['cwe']}  \n"
            f"**OWASP:** {c['owasp']}  \n"
            f"**Status:** Suspected{refer}",
            "",
            c["detail"],
            "",
        ]
    if not candidates:
        lines += ["_No hygiene candidates surfaced._", ""]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True, help="dir of {check}.json files")
    ap.add_argument("--target", required=True)
    ap.add_argument("--out", required=True, help="planning/{issue} dir")
    args = ap.parse_args()

    if not os.path.isdir(args.raw):
        print(f"ERROR: raw dir not found: {args.raw}", file=sys.stderr)
        return 1

    all_checks = [
        "archives", "block-lists", "carbon", "cookies", "dns", "dns-server",
        "dnssec", "firewall", "get-ip", "headers", "hsts", "http-security",
        "linked-pages", "location", "mail-config", "ports", "quality", "rank",
        "redirects", "robots-txt", "screenshot", "security-txt", "shodan",
        "sitemap", "social-tags", "ssl", "status", "subdomains", "tech-stack",
        "threats", "tls-connection", "tls-labs", "trace-route", "txt-records",
        "whois",
    ]
    data, ran = {}, []
    for c in all_checks:
        obj = load(args.raw, c)
        if obj is not None:
            data[c] = obj
            ran.append(c)

    os.makedirs(os.path.join(args.out, "webcheck"), exist_ok=True)

    with open(os.path.join(args.out, "WEBCHECK.md"), "w", encoding="utf-8") as fh:
        fh.write(render_snapshot(args.target, data, args.raw, ran))
    with open(os.path.join(args.out, "PASSIVE_RECON.patch.md"), "w", encoding="utf-8") as fh:
        fh.write(render_passive_patch(args.target, data))
    candidates = build_candidates(data)
    with open(os.path.join(args.out, "webcheck", "findings-candidates.md"), "w", encoding="utf-8") as fh:
        fh.write(render_candidates(args.target, candidates))

    print(f"normalized {len(ran)} checks -> WEBCHECK.md, PASSIVE_RECON.patch.md, "
          f"{len(candidates)} candidate(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
