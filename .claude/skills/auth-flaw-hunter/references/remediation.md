# remediation — auth-flaw-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia de Testes e Mitigação de Falhas de Autenticação.md` (Section 8: REMEDIATION)

---

## 1. Use Identical, Generic Error Messages

Account enumeration is the most common auth flaw. Fix: return the same
message, same response time, same status code for "user not found",
"wrong password", "account locked".

### Django

```python
from django.contrib.auth import authenticate
def login_view(request):
    user = authenticate(
        request,
        username=request.POST["username"],
        password=request.POST["password"],
    )
    if user is None:
        return render(request, "login.html", {"error": "Invalid credentials."})
    login(request, user)
```

Django's `authenticate` already returns `None` for both wrong user and
wrong password — don't add a branch that logs "user not found".

### Spring Security

```java
@Override
public UserDetails loadUserByUsername(String username) {
    return userRepo.findByUsername(username)
        .map(this::toUserDetails)
        .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
    // Do NOT throw UsernameNotFoundException here —
    // Spring maps it to a distinct "user not found" message by default.
}
```

### Node.js / Express

```javascript
app.post("/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  // ALWAYS hash the submitted password even if no user found (constant time)
  const dummyHash = "$2b$12$C6Uuvzw9FXx8GsX/8yYYY.fakehashforconstanttime";
  const hashToVerify = user?.passwordHash ?? dummyHash;
  const ok = await bcrypt.compare(req.body.password, hashToVerify);
  if (!user || !ok) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  // ... issue session / token
});
```

The dummy-hash compare ensures the timing is identical whether or not
the user exists.

---

## 2. Strict Rate Limiting + Lockout

Every authentication-adjacent endpoint needs rate limiting: login, MFA
challenge, password reset, account enumeration (e.g., `/forgot?email=`).

### Django — `django-ratelimit`

```python
from ratelimit.decorators import ratelimit

@ratelimit(key="ip", rate="5/m", block=True)
@ratelimit(key="post:email", rate="10/h", block=True)
def login_view(request):
    ...
```

### Flask — `flask-limiter`

```python
from flask_limiter import Limiter
limiter = Limiter(app, key_func=get_remote_address)

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
@limiter.limit("10 per hour", key_func=lambda: request.json.get("email"))
def login():
    ...
```

### Account lockout after N failures

Track failures server-side in Redis:

```python
def login(email, password):
    key = f"login_failures:{email}"
    failures = redis.get(key)
    if failures and int(failures) >= 10:
        log.warning("account_locked", extra={"email": email})
        return 429  # "Try again later"
    user = User.find(email)
    if not user or not user.check_password(password):
        redis.incr(key)
        redis.expire(key, 900)    # 15-minute window
        return 401
    redis.delete(key)
    return 200
```

### Lockout pitfalls to avoid

- Don't lock the account permanently — that's a DoS vector. Use a
  time-based cooldown or progressive delay.
- Don't lock per-username only — attackers rotate usernames. Track per-IP
  AND per-username (whichever trips first).
- CAPTCHA after N failures is a softer alternative than hard lockout.

---

## 3. TLS Everywhere

All authentication traffic must be HTTPS. Enforce via HSTS:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

Cookies MUST be `Secure; HttpOnly; SameSite=Lax`:

```python
response.set_cookie(
    "sessionid",
    value=token,
    secure=True,
    httponly=True,
    samesite="Lax",
    max_age=3600,
)
```

---

## 4. Enforce Multi-Stage Auth Server-Side

Multi-stage flows (password → MFA → success) must not be skippable by
directly calling the final stage. Store the intermediate state
server-side:

```python
# Stage 1: password verified, waiting for MFA
session["auth_stage"] = "mfa_pending"
session["auth_user_id"] = user.id

# Stage 2: verify MFA
def verify_mfa(request):
    if session.get("auth_stage") != "mfa_pending":
        abort(400)                    # cannot reach this without stage 1
    if not totp.verify(request.POST["code"]):
        abort(401)
    # elevate:
    session["auth_stage"] = "authenticated"
```

Never derive the "am I past stage 1" signal from a URL / cookie the
client controls.

---

## 5. MFA Code Entropy and Rate Limit

- MFA codes must be at least 6 digits — 4 digits = 10,000 attempts, bruteforceable.
- TOTP / HOTP is preferred over SMS (SIM-swap risk) for high-value accounts.
- Enforce rate limit on the MFA-verify endpoint (`5/min per session`).
- Mark MFA codes single-use server-side; invalidate on verification.

---

## 6. Consistent Policy Across Channels

Web, mobile API, partner API, SSO back-channel all share the same
auth backend. Enforce:
- Same rate-limit rules
- Same password complexity
- Same lockout policy
- Same logging / audit trail

Avoid "the mobile API is special; we turn off the lockout for mobile
users". Attackers find that path first.

---

## 7. Out-of-Band Notification on Sensitive Events

Email the registered address when:
- Password is changed
- Email address is changed
- MFA is enabled / disabled
- A new device logs in
- A recovery code is used

```python
def on_password_change(user):
    send_email(
        to=user.email,
        template="password_changed",
        context={"ip": request.remote_addr, "when": now()},
    )
```

This shortens the detection window for account takeover.

---

## 8. Password Storage

- Hash with `bcrypt` (cost >= 12), `argon2id`, or `scrypt`.
- Never `md5`, `sha1`, `sha256` (too fast), or unhashed.
- Salt automatically via these libraries; never roll your own.

```python
from argon2 import PasswordHasher
ph = PasswordHasher()
hashed = ph.hash(plain_password)
ph.verify(hashed, user_submitted)    # raises on mismatch
```

---

## 9. Credential Stuffing Defence

Credential stuffing uses valid credentials stolen from other breaches.
Detect with:
- Have-I-Been-Pwned's k-anonymity API — block passwords present in
  known breaches.
- Device-fingerprint anomaly detection — reject unfamiliar
  device + IP combinations.
- Risk-based auth — require step-up (MFA) when a login comes from a
  new IP / country / user-agent.

---

## 10. Secure Password Reset

- Reset tokens must be cryptographically random, single-use, time-limited
  (e.g. 15 minutes).
- Reset links must be delivered out-of-band (email) — never returned
  directly in the API response.
- Don't reveal whether an email address exists: "If the address is
  registered, you'll receive an email shortly."
- Invalidate all active sessions on password change.
- Log out all devices after password reset.

---

## Framework Quick-Reference

| Stack          | Canonical primitives                                                     |
|----------------|--------------------------------------------------------------------------|
| Django         | `authenticate()` + `login()`; `django-axes` for lockout                  |
| Flask          | `flask-login` + `flask-limiter`                                          |
| FastAPI        | `passlib` + `pyjwt`; Starlette middleware for rate limits                |
| Spring Security| `UserDetailsService` + `LockedException`; `AuthenticationFailureHandler` |
| Laravel        | Built-in `throttle` middleware; `Fortify` for lockout / password reset   |
| Rails          | `devise` + `devise-security` (paranoid + lockable + timeoutable)         |
| Express        | `passport.js` + `express-rate-limit`                                     |
| ASP.NET Core   | `Identity` with `LockoutOptions.MaxFailedAccessAttempts = 5`             |

---

## 11. Regression Tests

```python
def test_login_timing_identical_for_valid_invalid_user(client):
    import time
    t1 = time.perf_counter()
    client.post("/login", json={"email": "valid@example.com", "password": "wrong"})
    t_valid = time.perf_counter() - t1

    t2 = time.perf_counter()
    client.post("/login", json={"email": "doesnotexist@x", "password": "wrong"})
    t_invalid = time.perf_counter() - t2

    # Tolerance: the difference should be < 50 ms.
    assert abs(t_valid - t_invalid) < 0.05

def test_lockout_after_10_failures(client):
    for _ in range(11):
        r = client.post("/login", json={"email": "a@b", "password": "bad"})
    assert r.status_code == 429   # locked / throttled

def test_mfa_stage_cannot_be_skipped(client):
    # Try to call MFA-verify without a completed password stage
    r = client.post("/mfa-verify", json={"code": "000000"})
    assert r.status_code in (400, 401)
```
