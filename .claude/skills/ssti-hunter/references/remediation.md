# remediation — ssti-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Completo de Testes e Mitigação de SSTI.md` (Section 8: REMEDIATION), cross-referenced with the two other SSTI source notes that compose this skill.

---

## 1. Do Not Let Users Supply Templates

The canonical rule: user input becomes a **VALUE** for a pre-compiled
template, never a **TEMPLATE STRING** that the engine parses.

### Wrong — user input IS the template

```python
# WRONG — Jinja2
from jinja2 import Template
tpl = Template(f"Hello {user_input}, welcome!")      # user_input becomes template source
return tpl.render()
```

### Right — user input is a VALUE in a trusted template

```python
from jinja2 import Environment, FileSystemLoader, select_autoescape

env = Environment(
    loader=FileSystemLoader("templates/"),
    autoescape=select_autoescape(["html", "xml"]),
)
tpl = env.get_template("welcome.html")          # template is authored, not user-supplied
return tpl.render(user_input=user_input)        # user_input is a bound variable
```

---

## 2. Sandbox When User Templates Are Genuinely Required

If the feature explicitly allows users to author templates (CMS theme
editor, email-template designer), run the engine in a locked-down
sandbox.

### Jinja2 — `SandboxedEnvironment`

```python
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment(
    autoescape=True,
)
# SandboxedEnvironment blocks __class__, __mro__, __subclasses__, etc.
# Tighten further by subclassing if your threat model requires it.
tpl = env.from_string(user_template_source)
return tpl.render(safe_vars)
```

Still risky — SSTI bypasses of `SandboxedEnvironment` have been
demonstrated historically. Treat the template as data and apply an
additional content policy (size limit, tag-attribute allowlist).

### Twig — Sandbox extension

```php
use Twig\Extension\SandboxExtension;
use Twig\Sandbox\SecurityPolicy;

$policy = new SecurityPolicy(
    $allowedTags       = ['if', 'for'],
    $allowedFilters    = ['escape', 'upper', 'lower'],
    $allowedMethods    = [],
    $allowedProperties = [],
    $allowedFunctions  = []
);
$twig->addExtension(new SandboxExtension($policy, true /* sandbox globally */));
$twig->render('user_supplied.twig', $context);
```

### Freemarker — `TemplateClassResolver`

```java
Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
cfg.setAPIBuiltinEnabled(false);
cfg.setObjectWrapper(new DefaultObjectWrapperBuilder(Configuration.VERSION_2_3_32)
        .setExposeFields(false).build());
```

### Velocity — uberspector allowlist

```java
VelocityEngine ve = new VelocityEngine();
ve.setProperty(RuntimeConstants.RUNTIME_REFERENCES_STRICT, true);
ve.setProperty(RuntimeConstants.UBERSPECT_CLASSNAME,
    "org.apache.velocity.util.introspection.SecureUberspector");
ve.init();
```

### ERB — Switch to Liquid for user templates

Ruby ERB has no secure sandbox. If users MUST author templates, migrate
to Liquid (Shopify's intentionally-restricted engine):

```ruby
require "liquid"
template = Liquid::Template.parse(user_source)
template.render("name" => user_name)
```

Liquid does not expose Ruby objects, `eval`, or file system.

### Handlebars — `noEscape: false` + restricted helpers

```javascript
const Handlebars = require("handlebars");
const tpl = Handlebars.compile(user_source, { strict: true });
tpl(context);
// Review registered helpers — any helper that shells out is a path to RCE.
```

Do NOT ever `Handlebars.compile` user input without reviewing registered
helpers; `(lookup string.sub "constructor")` gadgets exist.

---

## 3. Disable Dangerous Built-ins When Possible

| Engine       | What to disable                                                              |
|--------------|------------------------------------------------------------------------------|
| Jinja2       | `{% extends %}` / `{% include %}` from dynamic paths                         |
| Twig         | `{% include %}` with user-supplied template name                             |
| Freemarker   | `?new`, `?eval`, `setObjectWrapper` defaults, `new Execute` class resolution |
| Velocity     | `$RuntimeRef.exec(...)`, `$context.getClass()`                               |
| Handlebars   | Custom helpers that call `exec` / `require`                                  |
| Smarty       | `{php}` tag (set `SMARTY_PHP_PASSTHRU = false`)                              |
| Mako         | `<%` Python blocks in user templates (compile with `strict_undefined=True`)  |

---

## 4. Input Sanitization + Error Handling

Even with a sandbox, validate input:

```python
import re

def validate_template(source: str) -> str:
    if len(source) > 10_000:
        raise ValueError("template too large")
    # Block obviously hostile patterns on top of the sandbox:
    if re.search(r"(__class__|__bases__|__subclasses__|__globals__|config)", source):
        raise ValueError("forbidden token in template")
    return source
```

Use generic error pages — do NOT reveal the template engine name in
stack traces. A verbose Jinja2 / Freemarker traceback tells an attacker
exactly which payloads to try.

```python
@app.errorhandler(500)
def handle_500(e):
    log.exception("template_error")           # full stack in internal logs only
    return render_template("500.html"), 500   # generic page to the user
```

---

## 5. Network Egress Filtering

A successful RCE often proceeds to fetch stage-2 payload. Block
outbound network from the app tier unless explicitly required:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-egress-restrictive
spec:
  podSelector: {app: myapp}
  policyTypes: [Egress]
  egress:
  - to:
    - podSelector: {app: postgres}
    ports: [{port: 5432, protocol: TCP}]
```

---

## 6. Keep Template Engines Patched

Known CVEs in template engines:
- Jinja2 — `SandboxedEnvironment` bypass via `str.format` (historical).
- Twig — multiple escape bypasses through 1.x, 2.x lifecycle.
- Freemarker < 2.3.30 — `setObjectWrapper` new()-instantiation.
- Handlebars < 4.0.14 — prototype-pollution via `__proto__` access.

Keep dependencies current and monitor security advisories for the
engine in use.

---

## Framework Quick-Reference

| Engine      | Primary Mitigation                                                       |
|-------------|--------------------------------------------------------------------------|
| Jinja2      | `SandboxedEnvironment`; `autoescape=True`; authored templates only       |
| Twig        | Sandbox extension + strict tag/filter allowlist                          |
| Freemarker  | `TemplateClassResolver.ALLOWS_NOTHING_RESOLVER`; disable API builtins    |
| ERB         | `ERB::Util.h` for user data; switch to Liquid for user templates         |
| Tornado     | No `{% import %}` in user templates; pre-compile templates only          |
| Velocity    | `SecureUberspector` + strict references + disable `Runtime.exec`         |
| Handlebars  | `noEscape: false`; never `compile(user_input)`; audit helpers            |
| Liquid      | Default-safe; audit any custom filter that wraps system calls            |
| Mako        | `strict_undefined=True`; disable Python `<% %>` in user templates        |
| Smarty      | Disable `{php}` tag; use Smarty security policy class                    |
| Thymeleaf   | Enforce Context Type; never use `th:text` with `#execInfo.getPid()`      |

---

## 7. Regression Tests

```python
def test_jinja2_rce_payload_blocked(client):
    payload = "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}"
    r = client.post("/render", json={"template": payload})
    assert r.status_code in (400, 500)
    assert "uid=" not in r.text

def test_jinja2_math_blocked(client):
    r = client.post("/render", json={"template": "{{7*7}}"})
    assert "49" not in r.text        # template is NOT evaluated

def test_sandbox_blocks_class_access(client):
    r = client.post("/render", json={"template": "{{ ''.__class__ }}"})
    assert r.status_code in (400, 500)
    assert "type" not in r.text.lower()
```
