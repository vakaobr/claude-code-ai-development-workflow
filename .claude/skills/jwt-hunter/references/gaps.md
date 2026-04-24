# gaps — jwt-hunter

**Source:** Author notes on what the source methodology did NOT cover.

The source (`Guia de Segurança e Testes em Vulnerabilidades JWT.md`)
focuses on signature-verification weaknesses and claim tampering. Gaps
worth flagging for a full JWT assessment:

---

## JWE (Encrypted JWT) Not Covered

The source discusses JWS (signed JWTs) exclusively. JWE adds:
- `alg` — key-wrap algorithm (RSA-OAEP, A256KW, dir)
- `enc` — content-encryption algorithm (A256GCM, A128CBC-HS256)
- Different attack surface: key-wrap confusion, GCM nonce reuse, CBC-HS
  padding issues, `crit` header handling.

If the target token has FIVE base64url-encoded segments separated by
four dots, it's JWE — the skill should stop and flag this as a
coverage gap.

## JWKS Key Rotation / Stale Key Caching

The source mentions JWKS in passing. A full audit should check:
- Is `kid` pinning enforced? (A token with a `kid` not in the current
  JWKS should be rejected.)
- Is the JWKS endpoint cached appropriately? (Too long → revoked keys
  still honoured. Too short → performance hit / DoS amplification.)
- Does the library refresh JWKS on unknown `kid` — and is there a
  rate limit on that, or can an attacker force unbounded refreshes?

## Blind `jku` Header SSRF

The payloads.md mentions `jku`-based public-key injection. A SECOND
attack via `jku` is SSRF — the server fetches the supplied URL before
rejecting it, leaking its outbound IP / enabling internal network probes
even without signature forgery. The source doesn't call this out.

## Short-Lived Tokens vs. Revocation Trade-Off

The source recommends "revocation on logout" but does not discuss the
architectural trade-off: stateless JWTs lose their main benefit once
you add a server-side blocklist. Modern guidance (OAuth 2.1) is:
access tokens are short-lived and NOT revoked; refresh tokens are
server-side records and CAN be revoked. The methodology is silent on
this distinction.

## Token Binding / DPoP / mTLS

Proof-of-possession mechanisms (RFC 8705 mTLS, RFC 9449 DPoP) bind a
JWT to a specific client TLS cert or key pair, so a stolen bearer token
is useless. Not covered by the source — worth testing whether the
target implements them and, if so, whether binding is verified.

## Confused-Deputy via Audience

Cross-service JWT reuse: `aud` set to `service-A` but accepted by
`service-B` (because both share an OIDC issuer). The methodology
notes `aud` only for false positives. Real test: get a token for the
user-facing API and try it on the admin API.

## `typ` / `cty` Header Abuses

`{"typ":"at+jwt"}` vs `{"typ":"JWT"}` vs `{"cty":"JWT"}` — wrapping a
JWT inside another JWT's content type can cause double-parsing issues.
Not covered.

## Session Fixation via `jti` Collision

A predictable `jti` (sequential, timestamp-based) enables session
fixation. The source focuses on HMAC-secret strength; `jti` entropy
isn't separately discussed.

## Session Cookie + JWT Hybrid

Many apps store a JWT in a cookie AND send it as a bearer header. The
skill should test both vectors — if only one path validates properly,
the weak path is the exploit path.
