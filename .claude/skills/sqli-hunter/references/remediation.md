# remediation — sqli-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Compreensivo de Auditoria e Testes de SQL Injection.md` (Section 8: REMEDIATION)

---

## 1. Parameterized Queries (Primary Defense)

Always separate query structure from data. The data path must never
build SQL via string concatenation.

### Python (psycopg2 / PostgreSQL)

```python
# WRONG
cur.execute(f"SELECT * FROM users WHERE id = {user_id}")

# RIGHT
cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### Python (SQLAlchemy ORM)

```python
user = session.query(User).filter(User.id == user_id).first()
# or with text()
session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})
```

### Django ORM

```python
# Safe — always parameterized
User.objects.filter(username=username)

# If raw is unavoidable:
User.objects.raw("SELECT * FROM auth_user WHERE id = %s", [user_id])
```

### Node.js (pg)

```javascript
// WRONG
await client.query(`SELECT * FROM users WHERE id = ${userId}`);

// RIGHT
await client.query("SELECT * FROM users WHERE id = $1", [userId]);
```

### Node.js (mysql2)

```javascript
await connection.execute(
  "SELECT * FROM users WHERE email = ? AND active = ?",
  [email, true]
);
```

### PHP (PDO)

```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $userId]);
```

### PHP (Laravel Eloquent / Query Builder)

```php
// Safe — Query Builder binds by default
DB::table('users')->where('id', $userId)->first();

// Raw — use bindings:
DB::select("SELECT * FROM users WHERE id = ?", [$userId]);
```

### Java (JDBC PreparedStatement)

```java
PreparedStatement stmt = conn.prepareStatement(
    "SELECT * FROM users WHERE id = ?"
);
stmt.setLong(1, userId);
ResultSet rs = stmt.executeQuery();
```

### Java (Spring JdbcTemplate)

```java
jdbcTemplate.queryForObject(
    "SELECT * FROM users WHERE id = ?",
    new Object[]{userId},
    User.class
);
```

### Go (database/sql)

```go
row := db.QueryRow("SELECT id, email FROM users WHERE id = $1", userID)
```

### C# / .NET (SqlCommand)

```csharp
using var cmd = new SqlCommand(
    "SELECT * FROM Users WHERE Id = @id", conn);
cmd.Parameters.AddWithValue("@id", userId);
```

---

## 2. Allowlist Validation for Non-Parameterizable Input

Table names, column names, and sort-direction values CANNOT be bound as
parameters. For these, validate against a hardcoded allowlist:

```python
ALLOWED_SORT_COLUMNS = {"id", "created_at", "email"}
ALLOWED_DIRECTIONS = {"ASC", "DESC"}

def safe_sort(column: str, direction: str) -> str:
    if column not in ALLOWED_SORT_COLUMNS:
        raise ValueError("invalid sort column")
    if direction.upper() not in ALLOWED_DIRECTIONS:
        raise ValueError("invalid direction")
    return f"ORDER BY {column} {direction.upper()}"
```

Do NOT sanitize with `.replace("'", "''")` or regex — these are incomplete.

---

## 3. Principle of Least Privilege (Database User)

The application-tier DB user should:
- Not own the schema (use a separate migration user for DDL).
- Have `SELECT`, `INSERT`, `UPDATE`, `DELETE` only on tables it needs.
- Not have `FILE`, `SUPER`, `CREATE`, `DROP`, `EXECUTE` privileges.
- Not be `root` / `sa` / `postgres`.

### PostgreSQL

```sql
CREATE ROLE app_user WITH LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE myapp TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
-- Explicitly revoke DDL:
REVOKE CREATE ON SCHEMA public FROM app_user;
```

### MySQL

```sql
CREATE USER 'app'@'%' IDENTIFIED BY '...';
GRANT SELECT, INSERT, UPDATE, DELETE ON myapp.* TO 'app'@'%';
-- Do NOT grant FILE, SUPER, or GRANT OPTION.
```

### MSSQL

```sql
CREATE LOGIN app_login WITH PASSWORD = '...';
CREATE USER app_user FOR LOGIN app_login;
EXEC sp_addrolemember 'db_datareader', 'app_user';
EXEC sp_addrolemember 'db_datawriter', 'app_user';
-- Keep away from sysadmin and db_owner.
```

---

## 4. Stored Procedure Security

Stored procedures are NOT automatically safe. If a procedure builds SQL
dynamically and executes it via `EXEC` / `sp_executesql`, it is still
injectable.

### MSSQL — Unsafe

```sql
CREATE PROCEDURE SearchUser @name NVARCHAR(50)
AS
BEGIN
    EXEC('SELECT * FROM users WHERE name = ''' + @name + '''')
END
```

### MSSQL — Safe

```sql
CREATE PROCEDURE SearchUser @name NVARCHAR(50)
AS
BEGIN
    EXEC sp_executesql
        N'SELECT * FROM users WHERE name = @name',
        N'@name NVARCHAR(50)',
        @name = @name
END
```

---

## 5. Defense in Depth

- **Generic error pages**: Replace DB error messages with a correlation ID
  and internal-only logging. An `HTTP 500 generic error` is better than
  `Unclosed quotation mark at character 42`.
- **Web Application Firewall (WAF)**: Deploy AWS WAF, Cloudflare, or
  ModSecurity with the OWASP Core Rule Set. A WAF is a compensating
  control — NOT a substitute for parameterized queries.
- **Logging and alerting**: Alert on DB errors from the application tier
  (they should be zero in steady-state).
- **Output encoding**: If user data is rendered in HTML, encode it — this
  mitigates second-order XSS regardless of the SQLi posture.

---

## Framework Quick-Reference

| Stack                 | Default-Safe API                                                                                   |
|-----------------------|----------------------------------------------------------------------------------------------------|
| Django                | ORM (`.filter()`, `.get()`); `raw()` with `params=`                                                |
| SQLAlchemy            | `session.query(Model).filter(...)`, `text(...)` with bind params                                   |
| FastAPI + SQLAlchemy  | Same as SQLAlchemy; rely on dependency-injected session                                            |
| Express + `pg`        | `client.query("... $1 ...", [param])`                                                              |
| Express + `mysql2`    | `connection.execute("... ? ...", [param])`                                                         |
| Laravel               | Eloquent / Query Builder (auto-binds); `DB::select("... ?", [param])` for raw                      |
| Symfony + Doctrine    | QueryBuilder with `setParameter()`                                                                 |
| Spring Data JPA       | Repository methods by name; `@Query(...)` with named parameters `:name`                            |
| Hibernate             | `Query` with `setParameter(name, value)`                                                           |
| ASP.NET Core EF Core  | `context.Users.Where(u => u.Id == id)`; `FromSqlInterpolated($"... {id}")` (auto-parameterizes)    |
| Ruby on Rails         | `User.where(id: id)` or `User.where("id = ?", id)`                                                 |
| Go + sqlx             | `db.Get(&dest, "... $1", param)` (pq) or `"... ?"` (mysql)                                         |

---

## 6. Regression Tests

Add negative tests that send malicious input and assert the application
returns clean data (not an error):

```python
def test_sqli_resistance_single_quote(client):
    r = client.get("/search?q=foo'bar")
    assert r.status_code == 200
    assert "syntax" not in r.text.lower()
    assert "error" not in r.text.lower()

def test_sqli_resistance_boolean(client):
    r1 = client.get("/search?q=foo' AND 1=1--")
    r2 = client.get("/search?q=foo' AND 1=2--")
    # Both should return the same (escaped-literal) result, or both 0 rows.
    assert len(r1.json()) == len(r2.json())
```
