# remediation — command-injection-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Estratégico de Injeção de Comandos no Sistema Operacional.md` (Section 8: REMEDIATION)

---

## 1. Avoid Shell Invocation Entirely

The single highest-impact fix. If you can solve the problem without
calling a shell — do.

### Python

```python
# WRONG — user input passed to shell
import os
os.system(f"ping -c 1 {host}")

# Better — argv form, no shell
import subprocess
subprocess.run(["ping", "-c", "1", host], check=True, timeout=5)

# Best — use a library that does what you need
import socket
socket.gethostbyname(host)      # DNS check without shelling out
```

### Node.js

```javascript
// WRONG
const { exec } = require("child_process");
exec(`ping -c 1 ${host}`, cb);

// Better — argv form
const { execFile, spawn } = require("child_process");
execFile("ping", ["-c", "1", host], cb);

// Best — use a Node library
const dns = require("dns").promises;
await dns.lookup(host);
```

### Java

```java
// WRONG
Runtime.getRuntime().exec("ping -c 1 " + host);

// RIGHT — argv form via ProcessBuilder
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", host);
pb.redirectErrorStream(true);
Process proc = pb.start();
```

### Go

```go
// WRONG
exec.Command("sh", "-c", "ping -c 1 "+host).Run()

// RIGHT
exec.Command("ping", "-c", "1", host).Run()
```

### PHP

```php
// WRONG
shell_exec("ping -c 1 $host");
exec("ping -c 1 $host");
system("ping -c 1 $host");

// Better (still dangerous — use allowlist validation)
exec("ping -c 1 " . escapeshellarg($host));

// Best — use the native socket / pcntl function family
gethostbyname($host);
```

### Ruby

```ruby
# WRONG
`ping -c 1 #{host}`
system("ping -c 1 #{host}")

# RIGHT
system("ping", "-c", "1", host)       # argv form
```

---

## 2. Strict Input Validation (Allowlist)

Never accept arbitrary strings for data that will be passed to a
subsystem — even argv-mode. Validate BEFORE invocation:

```python
import re

def validate_hostname(h: str) -> str:
    # Allow only letters, digits, dots, hyphens
    if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", h):
        raise ValueError("invalid hostname")
    return h

host = validate_hostname(request.args["host"])
subprocess.run(["ping", "-c", "1", host], check=True)
```

For integer inputs, parse and range-check:

```python
try:
    n = int(request.args["count"])
except ValueError:
    abort(400)
if not (1 <= n <= 10):
    abort(400)
```

---

## 3. Secure Argument-Escape Only If You Must

If an argv-form isn't possible (legacy systems), escape properly:

- **Python**: `shlex.quote(user_input)` for shell-quoted values.
- **PHP**: `escapeshellarg()` (NOT `escapeshellcmd` alone).
- **Ruby**: `Shellwords.escape(user_input)`.
- **Node.js**: `shell-quote` package.

```python
import shlex
cmd = f"mylegacy --input {shlex.quote(user_path)}"
subprocess.run(cmd, shell=True, check=True)
```

Escaping is a LAST resort — argv-mode is always preferred.

---

## 4. Parameterize APIs Where Available

For file operations, network utilities, etc., use the language stdlib
— not shell tools:

| Goal                          | Don't                                   | Do                                                 |
|-------------------------------|------------------------------------------|-----------------------------------------------------|
| Ping host                     | `os.system("ping ...")`                  | `socket.gethostbyname`, `icmplib` / `dns.asyncresolver` |
| Fetch URL                     | `os.system("curl ...")`                  | `requests.get`, `httpx.AsyncClient`                 |
| Create directory              | `os.system("mkdir -p ...")`              | `os.makedirs(path, exist_ok=True)`                  |
| Unzip archive                 | `os.system("unzip ...")`                 | `zipfile.ZipFile(...).extractall(...)`              |
| SSH to remote host            | `os.system("ssh ...")`                   | `paramiko.SSHClient` with key auth                  |
| Run git command               | `os.system("git clone ...")`             | `pygit2`, `dulwich`, `GitPython`                    |

---

## 5. Principle of Least Privilege

When you MUST shell out, ensure:
- The process runs under a dedicated low-privileged user
  (`www-data`, `app-user`) — not `root` / `Administrator`.
- The process has a minimal filesystem view (`chroot` jail or
  seccomp-bpf / AppArmor profile).
- Writes to sensitive paths (`/etc`, `/var/www`, `~/.ssh`) are
  explicitly denied via a SELinux / AppArmor policy.

### systemd hardening

```ini
# /etc/systemd/system/myapp.service
[Service]
User=app
Group=app
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
CapabilityBoundingSet=
ReadWritePaths=/var/lib/myapp
```

### Docker hardening

```dockerfile
RUN useradd -r app -u 1000
USER app:app
```

```yaml
# docker-compose.yml
services:
  app:
    read_only: true
    tmpfs:
      - /tmp:size=50M
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
```

---

## 6. Timeout and Resource Limits

Every shell invocation must have a timeout. A successful command injection
that causes a 60-second hang is a DoS on top of the injection.

```python
subprocess.run(cmd, timeout=5, check=True)
```

```java
proc.waitFor(5, TimeUnit.SECONDS);
if (proc.isAlive()) proc.destroyForcibly();
```

---

## Framework Quick-Reference

| Stack        | Safe pattern                                                                  |
|--------------|-------------------------------------------------------------------------------|
| Django       | Use `django-celery` or native Python libs; NEVER `subprocess(shell=True)`     |
| Flask/FastAPI| Same — argv-form `subprocess.run([...])` + allowlist                          |
| Express      | `execFile("bin", ["--arg", value])`; validate inputs with `zod` / `joi`       |
| NestJS       | Use a typed DTO + `class-validator`; delegate to native libs                  |
| Laravel      | Use `Symfony\Process` with argv array; NEVER string concatenation             |
| Spring Boot  | `ProcessBuilder(List.of(...))`; enforce with `@Validated` + `@Pattern`        |
| Go           | `exec.Command(bin, args...)`; reject `"bin --user-supplied-flag"` patterns    |
| Rust         | `std::process::Command::new(bin).args(&[a,b,c])`                              |

---

## 7. Sandbox for Legitimate Shell-Out Use Cases

If the functionality genuinely needs arbitrary subprocess execution
(CI/CD runner, build system), isolate it:

- Use gVisor, Firecracker, or Kata Containers — not plain Docker.
- Block egress network (`NetworkPolicy: egress: []` in Kubernetes).
- Mount only the specific inputs (ReadOnly) and the expected output dir
  (ReadWrite).
- Kill the process after a bounded time.

---

## 8. Regression Tests

```python
def test_command_injection_resistance_semicolon(client):
    r = client.get("/api/ping?host=127.0.0.1;id")
    assert r.status_code in (200, 400)
    assert "uid=" not in r.text

def test_command_injection_resistance_backtick(client):
    r = client.get("/api/ping?host=`id`")
    assert "uid=" not in r.text

def test_command_injection_time_based_not_reachable(client):
    import time
    t0 = time.time()
    r = client.get("/api/ping?host=127.0.0.1;sleep%205")
    elapsed = time.time() - t0
    assert elapsed < 3  # server rejected before sleep ran
```
