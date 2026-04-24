# remediation — deserialization-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Técnico de Desserialização Insegura e Metodologia de Testes.md` (Section 8: REMEDIATION)

---

## 1. Do Not Deserialize User-Supplied Objects

The strongest fix. If the data crosses a trust boundary, use a simple
schema-validated format (JSON, Protocol Buffers, Avro with a schema) —
NOT language-native serialization.

### Wrong vs right — Python

```python
# WRONG — pickle of untrusted input
import pickle, base64
obj = pickle.loads(base64.b64decode(cookie_value))

# RIGHT — validated JSON with a schema
from pydantic import BaseModel

class Session(BaseModel):
    user_id: int
    expires_at: int

obj = Session.parse_raw(base64.b64decode(cookie_value))
```

### Wrong vs right — Java

```java
// WRONG — readObject on arbitrary input
ObjectInputStream in = new ObjectInputStream(request.getInputStream());
Object o = in.readObject();

// RIGHT — Jackson with explicit DTO
ObjectMapper mapper = new ObjectMapper();
mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
mapper.deactivateDefaultTyping();                    // disable polymorphic
SessionDto dto = mapper.readValue(request.getInputStream(), SessionDto.class);
```

### Wrong vs right — Ruby

```ruby
# WRONG
obj = Marshal.load(base64_decode(cookie_value))

# RIGHT
require "json"
obj = JSON.parse(base64_decode(cookie_value), symbolize_names: true)
# Validate fields explicitly:
raise unless obj[:user_id].is_a?(Integer)
```

### Wrong vs right — PHP

```php
// WRONG
$obj = unserialize(base64_decode($_COOKIE['session']));

// RIGHT
$obj = json_decode(base64_decode($_COOKIE['session']), true);
// Validate:
if (!isset($obj['user_id']) || !is_int($obj['user_id'])) {
    http_response_code(400); exit;
}
```

---

## 2. Integrity-Protect Every Blob

If you MUST serialize and store server-created state on the client (e.g.,
for a stateless session), HMAC-sign it with a server-side secret:

```python
import hmac, hashlib, json, base64

SECRET = os.environ["SESSION_HMAC_KEY"].encode()

def sign(payload: dict) -> str:
    body = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(SECRET, body, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(body + b"." + sig).rstrip(b"=").decode()

def verify(token: str) -> dict:
    raw = base64.urlsafe_b64decode(token + "===")
    body, sig = raw.rsplit(b".", 1)
    expected = hmac.new(SECRET, body, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("bad signature")
    return json.loads(body)
```

Use a library when possible: `itsdangerous` (Python), `cookie-signature`
(Node), `MessageEncryptor`/`MessageVerifier` (Rails).

---

## 3. Class Allowlists (When Native Format Is Required)

If the application must deserialize its own binary format, restrict the
classes allowed.

### Java — `ObjectInputFilter` (JEP 290, since Java 9)

```java
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.session.*;java.lang.String;java.util.ArrayList;!*"
);
ObjectInputStream ois = new ObjectInputStream(input);
ois.setObjectInputFilter(filter);
Object o = ois.readObject();
```

Set globally via JVM flag:

```
-Djdk.serialFilter="com.myapp.**;java.lang.String;!*"
```

### Python — restricted unpickler

```python
import pickle, io

class Restricted(pickle.Unpickler):
    ALLOWED = {("myapp.session", "Session")}
    def find_class(self, module, name):
        if (module, name) in self.ALLOWED:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"disallowed: {module}.{name}")

obj = Restricted(io.BytesIO(blob)).load()
```

### Jackson — disable default typing

```java
ObjectMapper mapper = new ObjectMapper();
mapper.deactivateDefaultTyping();       // critical
// If polymorphism is genuinely required, use @JsonTypeInfo with a
// restricted allowlist:
mapper.activateDefaultTypingAsProperty(
    BasicPolymorphicTypeValidator.builder()
        .allowIfSubType("com.myapp.dto.")
        .build(),
    ObjectMapper.DefaultTyping.NON_FINAL,
    "@type"
);
```

### YAML safe loaders

```python
# Python
import yaml
data = yaml.safe_load(content)                  # NOT yaml.load

# Ruby
require "yaml"
data = YAML.safe_load(content, permitted_classes: [Symbol, Date])
```

### .NET — avoid BinaryFormatter

BinaryFormatter is deprecated (and unsafe by design). Use:

```csharp
// System.Text.Json — safe
var opts = new JsonSerializerOptions {
    TypeInfoResolverChain = { new DefaultJsonTypeInfoResolver() }
};
var obj = JsonSerializer.Deserialize<SessionDto>(json, opts);
```

---

## 4. Patch Known Gadget Libraries

Specific libraries are known sources of gadget chains. Keep them current
or replace:

| Library                                | Status / Action                                    |
|----------------------------------------|----------------------------------------------------|
| Apache Commons Collections < 3.2.2 / < 4.1 | Upgrade; CommonsCollections1/5 gadgets                   |
| Snakeyaml < 2.0                        | Upgrade to 2.0 (default safe constructor)          |
| Jackson-databind (any polymorphic use) | Upgrade + use BasicPolymorphicTypeValidator        |
| XStream                                | Upgrade to 1.4.21+; whitelist classes              |
| node-serialize                         | Deprecated; remove                                 |
| funcster                               | Deprecated; remove                                 |
| pyyaml with `yaml.load`                | Replace every `yaml.load` with `yaml.safe_load`    |

---

## 5. Network Egress Filtering

A gadget that tries to phone home for stage-2 payload fails if the
application server can't reach the internet. Block outbound from the
application tier to all destinations except required ones:

```yaml
# Kubernetes NetworkPolicy — allow only database + vault
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-egress
spec:
  podSelector: {app: myapp}
  policyTypes: [Egress]
  egress:
  - to:
    - podSelector: {app: postgres}
  - to:
    - podSelector: {app: vault}
```

---

## 6. Monitoring and Detection

Log every deserialization error. A sudden spike in `ClassNotFoundException`
/ `InvalidClassException` / `UnpicklingError` is a strong signal of
gadget-chain probing.

```python
try:
    obj = restricted_load(blob)
except pickle.UnpicklingError as e:
    logger.warning("deser_reject", extra={
        "event": "deserialization_rejected",
        "blob_prefix": blob[:16].hex(),
        "ip": request.remote_addr,
    })
    abort(400)
```

Alert rule: "N deserialization errors per minute from same IP" = likely
probe.

---

## Framework Quick-Reference

| Stack         | Canonical safe pattern                                                       |
|---------------|------------------------------------------------------------------------------|
| Django        | Use `signing.loads(...)` (HMAC-signed JSON), NOT `pickle`                    |
| Flask         | `itsdangerous.URLSafeTimedSerializer` for session state                     |
| Spring Boot   | Jackson with `deactivateDefaultTyping()`; avoid JDK serialization entirely   |
| Express       | `cookie-signature` + explicit DTOs via `zod`/`ajv`                           |
| Laravel       | Encrypted cookies by default; do not manually `serialize()` user input       |
| Ruby on Rails | `ActiveSupport::MessageEncryptor` / `MessageVerifier`; never `Marshal.load`  |
| ASP.NET Core  | `System.Text.Json`; never `BinaryFormatter`                                  |
| Go            | Standard `encoding/json` with defined structs — no risk surface              |

---

## 7. Regression Tests

```python
def test_session_rejects_tampered_blob(client, valid_token):
    # Flip one byte to simulate tampering
    tampered = bytearray(base64.urlsafe_b64decode(valid_token + "==="))
    tampered[0] ^= 0xFF
    new_token = base64.urlsafe_b64encode(bytes(tampered)).rstrip(b"=").decode()
    r = client.get("/api/me", cookies={"session": new_token})
    assert r.status_code == 401

def test_session_rejects_arbitrary_pickle(client):
    import pickle
    class X:
        def __reduce__(self):
            return (print, ("pwned",))
    blob = base64.b64encode(pickle.dumps(X())).decode()
    r = client.get("/api/me", cookies={"session": blob})
    assert r.status_code == 401
```
