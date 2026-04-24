---
name: sqli-hunter
description: "Tests user-input paths for SQL injection — error-based, Boolean-based, time-based, UNION-based, and authentication-bypass variants — across MySQL, PostgreSQL, MSSQL, Oracle, and SQLite backends. Use when endpoints pass URL params, body data, cookies, or headers into database queries; when responses leak DB error messages or reflect probe characters; or when the orchestrator's recon surfaces numeric/string parameters likely bound into WHERE clauses. Produces findings with CWE-89 mapping, per-payload request/response evidence, and parameterized-query remediation snippets. Defensive testing only, against assets listed in .claude/security-scope.yaml."
model: opus
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  WebFetch,
  Bash(curl:*), Bash(wget:*), Bash(httpx:*), Bash(ffuf:*),
  Bash(gobuster:*), Bash(nuclei:*), Bash(jq:*), Bash(arjun:*),
  Bash(gf:*), Bash(gau:*), Bash(waybackurls:*),
  Bash(nmap:--script=safe*), Bash(nmap:-sV), Bash(nmap:-Pn),
  Bash(dig:*), Bash(host:*), Bash(whois:*),
  Bash(openssl:s_client*), Bash(openssl:x509*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: injection
  authorization_required: true
  tier: T1
  source_methodology: "Guia Compreensivo de Auditoria e Testes de SQL Injection.md"
  service_affecting: false
  composed_from: []
---

# SQL Injection Hunter

## Goal

Test every user-controllable input that reaches the database layer for SQL
injection flaws — places where concatenation or incorrect escaping lets
attacker-supplied syntax alter the SQL statement the server executes. This
skill implements WSTG-INPV-05 and maps findings to CWE-89 (Improper
Neutralization of Special Elements used in an SQL Command). The goal is to
hand the engineering team a concrete list of vulnerable parameters with
request/response evidence, the DB engine fingerprinted, and parameterized-
query remediation for the ORM/driver in use (PDO, JDBC, sqlx, SQLAlchemy,
Sequelize, Eloquent, Active Record).

## When to Use

- Endpoints accept user input that is almost certainly passed to a
  relational database: numeric IDs (`/items/42`), search terms
  (`?q=shoes`), sort parameters (`?sort=price_desc`), filters.
- Probe characters (`'`, `"`, `;`, `--`) cause HTTP 500s or
  database-formatted error messages in responses.
- Response lengths change measurably when Boolean conditions are flipped
  (e.g., `?id=1 AND 1=1` vs `?id=1 AND 1=2`).
- Login forms or authentication bypass is a concern (`admin'--` family).
- The orchestrator selects this skill after `api-recon` or
  `web-recon-active` surfaces parameters bound to DB lookups.
- Sort/column parameters (`?sort=name`) that can't be parameterized are
  worth extra attention — those are the most common residual injection
  path in modern stacks.

## When NOT to Use

- For NoSQL injection (MongoDB `$where`, `$ne`, CouchDB, Firestore rules)
  — source methodology doesn't cover NoSQL; file a `gap` entry in
  `references/gaps.md` if NoSQL recon surfaces candidates.
- For LDAP / XPath / command injection — different classes with different
  payloads; use the matching hunter skill.
- For OS command injection that happens to involve a DB connection string
  — use `command-injection-hunter`.
- For Boolean-logic bugs that aren't SQL (e.g., IDOR ID guessing) — use
  `idor-hunter`.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not `active`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist or
   doesn't parse, halt and report.
2. Confirm the intended target appears in the `assets` list AND its
   `testing_level` is `active`.
3. SQL-injection testing can be destructive if payloads mutate the
   database. Use only read-side probes (SELECT, UNION, `SLEEP`, version
   fingerprint). NEVER execute `DROP`, `DELETE`, `UPDATE`, `INSERT`,
   `xp_cmdshell`, stacked-query writes, or `LOAD_FILE`/`INTO OUTFILE`
   even when `destructive_testing: approved` — this skill is defensive
   only.
4. If the target is ambiguous, write it to
   `.claude/planning/{issue}/SCOPE_QUESTIONS.md` and halt for that
   target only.
5. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log with
   status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the asset identifier from security-scope.yaml
- `{scope_context}`: optional — specific endpoints/parameters to focus on
- `{user_a}`: authenticated session for authenticated endpoints
- `{oob_listener}`: authorized OOB listener for out-of-band exfiltration
  variants (only used if blind methods fail and the scope file explicitly
  allows OOB traffic)

## Methodology

### Phase 1: Identify Database-Bound Parameters

1. **Inventory likely-bound parameters**
   [WAHH, Ch 9, p. 298]

   Do: Read `.claude/planning/{issue}/API_INVENTORY.md`. Extract
   parameters whose names or values suggest DB binding: numeric IDs
   (`user_id`, `product_id`), search terms (`q`, `query`, `search`),
   filters (`status`, `category`), sort/order (`sort`, `order_by`,
   `direction`), limit/offset pagination.

   Record: `.claude/planning/{issue}/sqli-targets.md` with each
   parameter's location (URL/body/header/cookie), baseline value, and
   response shape.

### Phase 2: Error-Based Detection

2. **Single-quote + semicolon probes** [WSTG v4.2, WSTG-INPV-05]

   Do: For each target, substitute the value with `'`, `"`, `;`, `\\`,
   `'--`, and observe the response.

   Vulnerable response: HTTP 500, or a response body containing
   DB-specific error signatures:
   - MySQL: `You have an error in your SQL syntax`, `Warning: mysql_`
   - PostgreSQL: `ERROR: syntax error at or near`, `unterminated quoted`
   - MSSQL: `Unclosed quotation mark after the character string`
   - Oracle: `ORA-00933`, `ORA-00921`
   - SQLite: `sqlite3.OperationalError`

   Not-vulnerable response: The page loads normally, or a generic 400
   error page appears that doesn't reveal DB syntax.

   Record: Any DB signature + the probe that triggered it.

3. **Fingerprint DB engine** [Hacking APIs, Ch 12, p. 256]

   Do: For confirmed injection points, submit version-disclosure
   payloads matching the engine suspected from error messages:
   - MySQL: `UNION SELECT @@version,NULL,...`
   - PostgreSQL: `UNION SELECT version(),NULL,...`
   - MSSQL: `UNION SELECT @@version,NULL,...`
   - Oracle: `UNION SELECT banner FROM v$version`
   - SQLite: `UNION SELECT sqlite_version(),NULL,...`

   Vulnerable response: Version banner in response body.

   Not-vulnerable response: Injection point is confirmed but UNION path
   is blocked (may still yield via time-based).

   Record: Engine + version per injection point.

### Phase 3: Boolean-Based Blind Detection

4. **Boolean-logic toggle probes** [Bug Bounty Bootcamp, Ch 11, p. 196]

   Do: For injection points where no error surfaces, submit
   logic-toggle probes adjacent to the baseline:
   ```
   {baseline} AND 1=1    (should match baseline)
   {baseline} AND 1=2    (should differ from baseline if injectable)
   {baseline}' AND '1'='1
   {baseline}' AND '1'='2
   ```

   Vulnerable response: Pages for `1=1` and `1=2` differ in length, body
   structure, or status.

   Not-vulnerable response: Response is identical regardless of Boolean
   condition.

   Record: Differential length/hash per probe.

### Phase 4: Time-Based Blind Detection

5. **DB-specific sleep probes** [zseano's methodology, p. 1201]

   Do: When Boolean probes are inconclusive, submit time-delay
   payloads. Use engine-appropriate syntax, with delay of 5 seconds:
   - MySQL: `' AND SLEEP(5)-- `
   - MySQL (blind subquery): `' AND (SELECT BENCHMARK(5000000,SHA1('a')))-- `
   - PostgreSQL: `'; SELECT pg_sleep(5)-- `
   - MSSQL: `'; WAITFOR DELAY '0:0:5'-- `
   - Oracle: `' AND DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)-- `

   Vulnerable response: Response time >=5 seconds for injection payload,
   baseline <1s.

   Not-vulnerable response: No time difference, or time difference
   observable on both baseline and payload (network jitter — re-run 3
   times and take median).

   Record: Timing data (min/median/max over 3 runs).

### Phase 5: UNION-Based Extraction

6. **Determine column count** [Bug Bounty Playbook V2, SQL Injection, p. 100]

   Do: For injection points with potential UNION path, submit `ORDER BY
   N` probes incrementing N until the query errors out. The last N that
   succeeded is the column count.
   ```
   ' ORDER BY 1-- 
   ' ORDER BY 2-- 
   ' ORDER BY 3-- 
   ...
   ' ORDER BY 50-- 
   ```

   Vulnerable response: `ORDER BY 4` succeeds, `ORDER BY 5` errors → 4
   columns.

   Alternative: `UNION SELECT NULL,NULL,NULL,...` incrementing NULLs.

   Record: Column count per injection point.

7. **Extract schema (read-only)** [Bug Bounty Playbook V2, p. 100]

   Do: Probe `information_schema` (MySQL/PostgreSQL/MSSQL) or
   `sqlite_master` (SQLite) using a UNION payload. ONLY extract table
   names and column names — do NOT dump user data.

   ```
   ' UNION SELECT table_name,NULL,NULL FROM information_schema.tables-- 
   ```

   Vulnerable response: Table names appear in the response.

   Record: Presence of sensitive table names (`users`, `credentials`,
   `sessions`) as a finding. Do NOT proceed to dump contents; the
   finding is the ability to extract, not the extracted data.

### Phase 6: Authentication Bypass

8. **Login-form bypass probes**
   [Bug Bounty Bootcamp, Ch 11, p. 196]

   Do: For login/authentication endpoints, submit classic bypass
   payloads in the username field:
   ```
   admin'-- 
   admin' OR '1'='1'-- 
   ' OR 1=1-- 
   admin') OR ('1'='1
   ```
   Leave the password field blank or with any value.

   Vulnerable response: Session cookie set, or redirect to authenticated
   area.

   Not-vulnerable response: Login fails with generic "invalid
   credentials".

   Record: If bypass succeeds, file a FINDING-NNN at Critical severity
   (auth bypass with access to another user's context).

### Phase 7: WAF-Evasion Probing (only when clean probes fail)

9. **Encoding and comment-splitting evasion** [Bug Bounty Playbook V2]

   Do: If an injection is suspected but clean probes are blocked by a
   WAF, retry with:
   - URL-encoding: `%27%20OR%20%271%27%3D%271`
   - Double-encoding: `%2527`
   - Comment-split keywords: `SEL/*foo*/ECT`, `UN/**/ION`
   - Case variation: `uNiOn SeLeCt`
   - Hex encoding for string values: `0x726F6F74` instead of `'root'`
   - MySQL-specific comment: `/*!50000SELECT*/`

   Vulnerable response: Encoded payload triggers the same response
   signature as the clean payload would.

   Record: Note both the WAF-evasion vector AND the underlying
   injection as the root cause; remediation is fixing the injection,
   not tuning the WAF.

## Payload Library

Full payloads in `references/payloads.md`. Categories:

- **Auth bypass**: `admin'-- `, `' OR '1'='1`, `'))) OR ((('1'='1`
- **Error-triggers**: `'`, `"`, `;--`, `\\`, malformed comments
- **Boolean toggles**: `AND 1=1` / `AND 1=2` variants in string vs
  numeric contexts
- **Time-based**: per-engine `SLEEP`/`WAITFOR`/`pg_sleep`/`BENCHMARK`
- **UNION enumeration**: `ORDER BY N`, `UNION SELECT NULL,NULL,...`
- **Schema enumeration** (read-only): information_schema queries
- **Second-order**: payloads stored in profile fields that trigger on
  a later endpoint's query
- **WAF evasion**: URL-encoding, comment splitting, case variation,
  hex encoding

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per the
schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-89 (SQL Injection). Add CWE-20 for input-validation
  gaps. For auth bypass, add CWE-287.
- **OWASP**: WSTG-INPV-05. For APIs, map to OWASP API8:2019 (Injection).
  Top 10 2021: A03:2021.
- **CVSS vectors**: read-level injection typically
  `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`. Auth bypass:
  `...PR:N/.../C:H/I:H/A:N`. RCE via `xp_cmdshell` /
  `COPY FROM PROGRAM`: `...C:H/I:H/A:H` (but testing for those is
  excluded by this skill's authorization contract — flag as
  "escalation path known, not tested").
- **Evidence**: the exact probe, the response signature (DB error
  message, timing data, or UNION result), the fingerprinted engine and
  version, and a baseline response for comparison.
- **Remediation framing**: backend engineer. Include driver-specific
  parameterized-query snippets in `references/remediation.md` for PDO
  (PHP), PreparedStatement (Java/JDBC), sqlx (Go), SQLAlchemy (Python),
  psycopg2 (Python), Sequelize (Node), Eloquent (Laravel), Active
  Record (Rails).

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every finding has a baseline response AND an injection response
      showing the signature (error/timing/length diff)
- [ ] Every finding names the DB engine and version when known
- [ ] No finding used a destructive payload (DROP/DELETE/UPDATE/xp_cmdshell)
- [ ] No UNION query was used to dump user records — only schema names
- [ ] Remediation snippets match the detected driver / ORM
- [ ] Time-based findings report median-of-3-runs to rule out jitter
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Business-logic errors look like SQL errors**: A 500 caused by a
  validation check (not a SQL syntax error) can be misread as SQL
  injection. Distinguish by triggering with a SQL metacharacter AND a
  benign-but-invalid value — if both produce 500 with similar bodies,
  it's a generic error handler, not SQLi.

- **Performance-induced delays**: Slow responses can be misread as
  time-based injection during load. Confirm with 3 runs and compare
  against a 3-run baseline of a clean parameter. If both show high
  variance, the delay is network-side, not DB-side.

- **Reflected alphanumeric strings**: The probe string appears in the
  response body, but not because it was executed — the app just echoes
  the user input. Confirm by trying probes that produce observable
  side effects (math, errors, delays) rather than relying on reflection
  alone.

- **Session-state confusion**: A different response on the second
  probe can be caused by session state, cache invalidation, or another
  user's activity — not by the probe's logic. Run probes back-to-back
  and compare timestamps.

- **False negatives from second-order injection**: Input stored via one
  endpoint and executed at another. If the first-order path looks
  clean, also test whether user-editable fields (username, profile
  bio, comment bodies) feed later queries.

## References

- `references/payloads.md` — full payload catalog per category and
  engine
- `references/remediation.md` — parameterized-query snippets per
  driver/ORM

External:
- WSTG-INPV-05: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- OWASP SQL Injection Prevention Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- PortSwigger SQL injection labs:
  https://portswigger.net/web-security/sql-injection

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Guia Compreensivo de Auditoria e Testes de SQL Injection.md`

Grounded in:
- The Web Application Hacker's Handbook, Ch 9 (Injecting Code)
- Bug Bounty Bootcamp, Ch 11 (SQL Injection)
- Bug Bounty Playbook V2 (SQL Injection chapter)
- Hacking APIs, Ch 12 (API Injection)
- OWASP WSTG v4.2 (WSTG-INPV-05)
- zseano's methodology (SQL Injection)

Conversion date: 2026-04-24
Conversion prompt version: 1.0
