# remediation — jwt-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia de Segurança e Testes em Vulnerabilidades JWT.md` (Section 8: REMEDIATION)

---

## 1. Always Validate the Signature Server-Side

Signature verification must be a non-skippable step on the protected-route
path. The code should not have a branch where an invalid/missing
signature path still yields a decoded payload that gets used.

### Python — `PyJWT`

```python
# WRONG
payload = jwt.decode(token, options={"verify_signature": False})

# RIGHT — explicit algorithm allowlist, audience and issuer checks
payload = jwt.decode(
    token,
    key=JWT_SECRET,
    algorithms=["HS256"],          # allowlist — blocks alg:none and confusion
    audience="my-api",
    issuer="https://auth.example",
    options={"require": ["exp", "iat", "sub"]},
)
```

### Node.js — `jsonwebtoken`

```javascript
// WRONG
const decoded = jwt.decode(token);        // does NOT verify

// RIGHT
const decoded = jwt.verify(token, JWT_SECRET, {
  algorithms: ["HS256"],                  // allowlist
  audience: "my-api",
  issuer: "https://auth.example",
  clockTolerance: 5,                      // 5 seconds
});
```

### Java — `jjwt`

```java
Claims claims = Jwts.parserBuilder()
    .setSigningKey(JWT_SECRET.getBytes(StandardCharsets.UTF_8))
    .requireIssuer("https://auth.example")
    .requireAudience("my-api")
    .build()
    .parseClaimsJws(token)                // throws on invalid signature
    .getBody();
```

### Go — `github.com/golang-jwt/jwt/v5`

```go
token, err := jwt.Parse(
    tokenString,
    func(t *jwt.Token) (interface{}, error) {
        // HS256-ONLY: reject any other alg
        if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
        }
        return []byte(secret), nil
    },
    jwt.WithValidMethods([]string{"HS256"}),
    jwt.WithIssuer("https://auth.example"),
    jwt.WithAudience("my-api"),
)
```

### Spring Security (OAuth 2 Resource Server)

```yaml
# application.yml — delegate to Spring's JWT decoder with a fixed JWKS
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: https://auth.example/.well-known/jwks.json
```

```java
@Configuration
public class JwtConfig {
  @Bean
  JwtDecoder jwtDecoder() {
    NimbusJwtDecoder decoder = NimbusJwtDecoder
        .withJwkSetUri("https://auth.example/.well-known/jwks.json")
        .jwsAlgorithm(SignatureAlgorithm.RS256)           // pin algorithm
        .build();
    decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer("https://auth.example"));
    return decoder;
  }
}
```

---

## 2. Use Strong, Long Secrets

For HMAC (HS256/384/512), the signing key must be at least as long as the
hash size:
- HS256 → 32 random bytes
- HS384 → 48 random bytes
- HS512 → 64 random bytes

Generate with a CSPRNG:

```bash
openssl rand -base64 64
# or
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

Store in a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure
Key Vault), NOT in a config file or environment variable committed to
the repo.

---

## 3. Disable / Block Weak Algorithms

Explicitly reject:
- `none`
- `HS256` when an RS256-signed token is expected (algorithm confusion)
- Any algorithm not on your allowlist

Set the allowlist in EVERY JWT verification call — not globally.

```python
ALLOWED_ALGS = ["RS256"]       # or ["HS256"] — never both
jwt.decode(token, key=pub_key, algorithms=ALLOWED_ALGS, ...)
```

---

## 4. Enforce `exp`, `iat`, `nbf`

Always require and validate:
- `exp` (expiration) — most libraries check automatically; verify you
  don't have `verify_exp: False` anywhere.
- `iat` (issued-at) — reject tokens issued "in the future" beyond a
  clock skew of a few seconds.
- `nbf` (not-before) — respect the not-before claim if present.

Short `exp` values reduce blast radius:
- Access token: 15 minutes
- Refresh token: 7-30 days, stored server-side / revocable

---

## 5. Add Server-Side Revocation

Plain stateless JWT has no revocation. For high-sensitivity flows:
- Keep a short-lived access token + a server-side refresh token stored
  in Redis / database. Revoke the refresh record on logout / password
  change.
- OR maintain a blocklist of `jti` (token ID) keyed in Redis with TTL =
  remaining `exp`.

```python
# Python — verify the jti is not blocklisted
def verify_token(token):
    claims = jwt.decode(token, ..., algorithms=["RS256"])
    if redis.get(f"blocklist:{claims['jti']}"):
        raise TokenRevoked()
    return claims
```

---

## 6. Rotate Keys, Use JWKS

- Host `/.well-known/jwks.json` so clients can fetch current public keys.
- Rotate keys periodically (e.g., quarterly) and keep the previous key
  valid for the overlap window.
- The `kid` header tells the verifier which key to use — and the server
  should reject tokens with unknown `kid` values.

```json
{
  "keys": [
    {"kty":"RSA","kid":"2026-04","n":"...","e":"AQAB","use":"sig"},
    {"kty":"RSA","kid":"2026-01","n":"...","e":"AQAB","use":"sig"}
  ]
}
```

---

## 7. Do Not Put Secrets in the Payload

The payload is base64url-encoded, not encrypted. Anyone with the token
can read it. Do NOT include:
- Passwords, even hashed
- PII beyond what the session needs
- Internal database row IDs the client shouldn't know about

If confidentiality is required, use a JWE (JSON Web Encryption) or a
server-side opaque reference token instead.

---

## 8. Rotate Tokens on Privilege Change

Issue a fresh JWT with updated claims after:
- Login (always)
- Password change
- Privilege elevation (2FA confirmation)
- Significant permission grant

Invalidate the old token in the blocklist.

---

## Framework Quick-Reference

| Stack                 | Correct verification call                                                                 |
|-----------------------|-------------------------------------------------------------------------------------------|
| Django                | `python-jose` / `djangorestframework-simplejwt` with algorithm allowlist                  |
| Flask                 | `PyJWT` + `jwt.decode(..., algorithms=[...], audience=..., issuer=...)`                   |
| FastAPI               | `from jose import jwt; jwt.decode(token, key, algorithms=[...])`                          |
| Express               | `jsonwebtoken` + `jwt.verify(token, key, { algorithms: [...], audience, issuer })`        |
| NestJS                | `@nestjs/passport` + `passport-jwt` (pass `algorithms` option)                            |
| Spring Security       | `NimbusJwtDecoder.withJwkSetUri(...).jwsAlgorithm(...)`                                   |
| Laravel               | `tymon/jwt-auth` or `firebase/php-jwt` with `JWT::decode($token, $key, ['HS256'])`        |
| ASP.NET Core          | `AddJwtBearer(...)` — configure `TokenValidationParameters` with `ValidAlgorithms`        |
| Go                    | `golang-jwt/jwt/v5` with `ParserOption` `WithValidMethods`                                |
| Ruby                  | `ruby-jwt` with `JWT.decode(token, key, true, { algorithms: [...] })`                     |

---

## 9. Regression Tests

```python
def test_jwt_rejects_alg_none(client, valid_token_payload):
    import jwt
    forged = jwt.encode(valid_token_payload, "", algorithm="none")
    r = client.get("/api/me", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401

def test_jwt_rejects_tampered_claim(client, valid_token_payload, signing_key):
    import jwt
    # Alice signs, then tamper payload, keep signature
    alice = jwt.encode(valid_token_payload, signing_key, algorithm="HS256")
    parts = alice.split(".")
    import base64, json
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==="))
    payload["role"] = "admin"
    tampered_payload = base64.urlsafe_b64encode(
        json.dumps(payload).encode()).rstrip(b"=").decode()
    forged = f"{parts[0]}.{tampered_payload}.{parts[2]}"
    r = client.get("/api/admin", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code in (401, 403)

def test_jwt_rejects_rs256_downgrade(client, rsa_public_pem):
    # Sign with HS256 using the public key as a "secret"
    import jwt
    forged = jwt.encode({"sub": "alice", "role": "admin"}, rsa_public_pem,
                        algorithm="HS256")
    r = client.get("/api/me", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401
```
