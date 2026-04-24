# gaps — oauth-oidc-hunter

**Source:** Author notes on what the source methodology did NOT cover.

The source (`Guia de Vulnerabilidades em OAuth 2.0 e OpenID Connect.md`)
covers redirect-URI manipulation, state CSRF, code reuse, and flow
switching. Gaps worth flagging for a full OAuth / OIDC assessment:

---

## PKCE (Proof Key for Code Exchange) Audit

The source does not discuss PKCE. For public clients (SPAs, mobile), OAuth
2.1 requires PKCE with `S256` challenge method. Gaps to test:
- Missing `code_challenge` / `code_verifier` entirely.
- `plain` (non-hashed) challenge method accepted.
- Code exchange without PKCE still succeeds even when the auth-request
  included PKCE (downgrade).

## Token Endpoint Authentication Method

Confidential clients should authenticate via `client_secret_basic`,
`client_secret_post`, `private_key_jwt`, or `tls_client_auth`. Test:
- Whether `none` (public client) is accepted when `client_secret` was
  expected.
- Whether a public client's presence of a `client_secret` is honoured
  (client-type confusion).
- Replay of a `private_key_jwt` assertion (should be single-use via `jti`).

## Scope Escalation / Scope Confusion

An authorization request for `scope=profile` that returns a token with
`scope=profile admin` is an escalation. The source mentions "token
scope limitation" as remediation but doesn't include a scope-escalation
test.

## Refresh-Token Rotation

OAuth 2.1 recommends refresh-token rotation: each refresh exchange
returns a NEW refresh token, and reuse of an old one invalidates the
whole family. Test:
- Is rotation enforced?
- Does refresh-token theft + legitimate use by the victim trigger
  invalidation?

## Device Authorization Grant (RFC 8628)

IoT and smart TVs use the device grant. Not covered by the source.
Test:
- Brute force of `user_code` during its short validity (entropy matters).
- Race conditions on `device_code` exchange.
- Missing IP / TTL enforcement on the polling endpoint.

## JWT-Secured Authorization Request (JAR / PAR)

Modern specs push clients to send authorization requests as signed
JWTs to prevent tampering. Gaps:
- Is JAR / Pushed Authorization Request (PAR) supported?
- If supported, is the `request_uri` resolvable to an attacker-controlled
  URL (SSRF)?
- Is the signature algorithm pinned (same as JWT flaws)?

## ID Token vs Access Token Confusion

OIDC `id_token` is for client identity, NOT for API authorization.
Test whether an API accepts `id_token` as a bearer token — if so,
any client that can log the user in can call the API.

## Subject-Identifier Spoofing

For pairwise pseudonymous subject identifiers (`sub=pairwise`), test:
- Does the RP validate `sub` + `iss` together (not just `sub`)?
- Can a different IdP's token with the same `sub` log someone in?

## Token Revocation

RFC 7009 token revocation is often not implemented, or not enforced.
Test:
- `/oauth/revoke` — does the access token stop working immediately
  after revocation?
- Are refresh tokens revoked when the access token is revoked?
- Are sibling sessions revoked on password change?

## Front-Channel Logout (RP-Initiated Logout)

OIDC's `end_session_endpoint` can be abused:
- Open-redirect via `post_logout_redirect_uri`.
- CSRF in logout endpoints if no state is required.

## `prompt=none` Silent Authentication

Silent auth can be abused as an oracle:
- Send `prompt=none` to learn whether a session exists at the IdP.
- Useful for targeted attacks — not a vulnerability on its own, but
  a reconnaissance signal.

## Token Binding Absence

Without DPoP / mTLS token binding, a stolen bearer token is usable by
any caller. Audit whether binding is specified AND enforced.

## Mix-Up Attacks (Multi-IdP)

When the RP supports multiple IdPs, the mix-up attack tricks the RP
into exchanging a code from IdP-A at IdP-B's token endpoint. The
source doesn't cover multi-IdP scenarios.

## SAML-Alongside-OIDC

When the same product supports OIDC AND SAML, cross-protocol attacks
are possible (e.g., a SAML assertion confused as an OIDC `id_token`).
The source is OIDC/OAuth-only; SAML interop is its own audit class.

## Dynamic Client Registration (DCR)

RFC 7591 DCR allows clients to self-register. Test:
- Can an attacker register a client with a malicious `redirect_uri`?
- Is DCR authenticated / rate-limited?
- Does the IdP still honor client-type restrictions (public vs
  confidential) on DCR-registered clients?
