# remediation — xxe-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Completo de Segurança e Testes em Ataques XXE.md` (Section 8: REMEDIATION)

The canonical fix is to disable external entity resolution on every XML
parser. Listing the primary libraries below.

---

## 1. Disable DTDs / External Entities (Primary Fix)

### Python — `lxml`

```python
from lxml import etree

# WRONG (default parser resolves entities)
parser = etree.XMLParser()

# RIGHT — reject DTDs and external entities outright
parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    load_dtd=False,
)
root = etree.fromstring(xml_bytes, parser=parser)
```

### Python — `xml.etree.ElementTree`

Python stdlib is safe against most XXE by default, but `ElementTree`
does not use `expat`'s `external_entity_ref_handler`. For defense in
depth, use `defusedxml`:

```python
from defusedxml.ElementTree import fromstring
root = fromstring(xml_bytes)     # raises EntitiesForbidden / ExternalReferenceForbidden
```

### Python — `xml.sax`

```python
from defusedxml.sax import make_parser
parser = make_parser()
```

### Java — JAXP (DocumentBuilderFactory, SAXParserFactory, etc.)

```java
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;

DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

### Java — Transformer

```java
TransformerFactory tf = TransformerFactory.newInstance();
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
```

### Node.js — `libxmljs2`

```javascript
const libxml = require("libxmljs2");
// Explicitly disable network and external entities
const doc = libxml.parseXml(xml, { noent: false, dtdload: false, nonet: true });
```

Note: Node's built-in `DOMParser` (via JSDOM) does not resolve external
entities, but `fast-xml-parser` and `xml2js` may — always verify the
library's defaults.

### .NET — XmlReader / XmlDocument

```csharp
// WRONG — XmlResolver is non-null by default on older frameworks
var doc = new XmlDocument();

// RIGHT
var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver  = null,
};
using var reader = XmlReader.Create(input, settings);

var doc = new XmlDocument { XmlResolver = null };
doc.Load(reader);
```

### PHP — libxml

```php
// Global disable (recommended on every request)
libxml_disable_entity_loader(true);             // PHP < 8.0
// PHP >= 8.0 sets this to true by default — do not override

// SimpleXML
$xml = simplexml_load_string(
    $input,
    "SimpleXMLElement",
    LIBXML_NOENT & ~LIBXML_NOENT     // do NOT enable LIBXML_NOENT
);

// DOMDocument
$doc = new DOMDocument();
$doc->loadXML($input, LIBXML_NONET | LIBXML_DTDLOAD ^ LIBXML_DTDLOAD);
```

### Ruby — REXML / Nokogiri

```ruby
# REXML — safe by default in recent versions; explicit:
require "rexml/document"
REXML::Document.entity_expansion_limit = 0

# Nokogiri — disable DTD load and entities:
Nokogiri::XML(input) do |config|
  config.strict.nononet.noent(false)
end
```

### Go — `encoding/xml`

Go's standard library `encoding/xml` does NOT resolve external entities
by default. Leave it that way — do not introduce a third-party parser
that re-enables them.

### Python — `xmltodict`

Uses `expat` under the hood; configure:

```python
import xmltodict
# xmltodict passes kwargs through to expat; disable_entities blocks XXE
data = xmltodict.parse(xml_str, disable_entities=True)
```

---

## 2. Disable XInclude

```java
// Java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setXIncludeAware(false);
dbf.setFeature("http://apache.org/xml/features/xinclude", false);
```

```python
# Python lxml
parser = etree.XMLParser(resolve_entities=False)
# Do NOT call parser.XInclude() on user input
```

---

## 3. Network Egress Filtering

Even with parsers locked down, block application tier outbound network
access to `169.254.169.254` (IMDS) and to internal RFC1918 ranges not
required by the service. This stops SSRF-via-XXE from reaching cloud
credentials even if a parser regression is introduced.

```text
# Example egress policy (AWS Security Group / NetworkPolicy concept):
#   allow: PostgreSQL (10.0.1.0/24:5432), S3 (via VPC endpoint)
#   deny:  0.0.0.0/0  and 169.254.0.0/16
```

---

## 4. Input Validation at the Boundary

Reject payloads containing `<!DOCTYPE`, `<!ENTITY`, or `<xi:include` at
the HTTP reverse proxy (Nginx, Envoy, API Gateway) before the XML ever
reaches the application. This is a defence-in-depth measure — the
primary defence is the parser configuration.

```nginx
location /api/xml {
  if ($request_body ~* "<!DOCTYPE|<!ENTITY|<xi:include") {
    return 400;
  }
  proxy_pass http://upstream;
}
```

---

## 5. Use JSON Where Possible

If the endpoint can accept JSON, deprecate XML. JSON parsers do not have
external-entity resolution, so XXE is structurally impossible.

---

## 6. Keep Dependencies Patched

XXE bugs have been found in otherwise-hardened parsers (Xerces, libxml2,
Apache POI). Ensure:
- `libxml2` >= 2.9.0 (default `noent=false`)
- Apache POI >= 3.10.1
- Java `xerces` shipped with the current JDK (use `XMLConstants.FEATURE_SECURE_PROCESSING`)

---

## Framework Quick-Reference

| Language / Framework   | Default-Safe Parser / Setting                               |
|------------------------|-------------------------------------------------------------|
| Python stdlib          | `defusedxml.ElementTree.fromstring` (wraps `xml.etree`)     |
| Python `lxml`          | `XMLParser(resolve_entities=False, no_network=True, load_dtd=False)` |
| Java JAXP              | `FEATURE_SECURE_PROCESSING` + `disallow-doctype-decl`       |
| Spring Boot            | Configure global `Jaxb2Marshaller` with secure features     |
| .NET (new)             | `XmlReaderSettings { DtdProcessing = Prohibit, XmlResolver = null }` |
| .NET (legacy)          | Set `XmlDocument.XmlResolver = null`                        |
| PHP >= 8.0             | Safe by default (`libxml_disable_entity_loader` == true)    |
| Node.js `fast-xml-parser` | Option `processEntities: false`                          |
| Node.js `xml2js`       | Option `strict: true` (does not disable entities on its own; prefer `fast-xml-parser`) |
| Ruby Nokogiri          | `Nokogiri::XML(input) { |c| c.nononet.noent(false) }`      |
| Go `encoding/xml`      | Safe by default                                             |

---

## 7. Regression Tests

```python
def test_xxe_external_entity_rejected(client):
    payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>&xxe;</root>'''
    r = client.post("/api/xml", data=payload,
                    headers={"Content-Type": "application/xml"})
    assert r.status_code in (400, 422)
    assert "root:x:" not in r.text
```
