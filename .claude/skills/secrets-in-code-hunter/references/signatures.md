# signatures — secrets-in-code-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Segredos em Código_ Detecção e Resposta a Vazamentos.md` (Section 3: DETECTION SIGNALS) + community provider patterns.

Detection regexes grouped by credential type. Use these as Grep
patterns over the working copy AND the git history (`git log -p`).
Tools like `gitleaks`, `trufflehog`, and `detect-secrets` ship with
overlapping rulesets — this document consolidates the high-signal
patterns.

---

## Universal Best-Practice First

Always run a specialist tool in CI — these regexes are the manual
fallback / reference:

```bash
# Gitleaks — fast, scans git history
gitleaks detect --source=. --verbose

# TruffleHog — higher-entropy detection + verification
trufflehog filesystem --directory=. --only-verified

# detect-secrets
detect-secrets scan --all-files
```

---

## AWS

```
# Access Key ID
AKIA[0-9A-Z]{16}

# AWS Secret Access Key — 40 chars of base64 alphabet
(?i)aws(.{0,20})?(?-i)['"][0-9a-zA-Z/+]{40}['"]

# Temporary (STS) credentials
ASIA[0-9A-Z]{16}

# Session token (common)
(?i)aws_session_token\s*[:=]\s*['"]?[A-Za-z0-9/+=]{100,}['"]?
```

## GitHub

```
# Personal access token (classic)
ghp_[0-9A-Za-z]{36}

# Fine-grained personal token (2022+)
github_pat_[0-9A-Za-z_]{82}

# OAuth application token
gho_[0-9A-Za-z]{36}

# GitHub app installation token
ghs_[0-9A-Za-z]{36}

# Refresh / user-to-server token
ghr_[0-9A-Za-z]{36}

# Legacy token
(?i)github[_-]?(pat|token|key)\s*[:=]\s*['"]?[A-Za-z0-9]{40}['"]?
```

## GitLab

```
# Personal access token (recent format)
glpat-[0-9a-zA-Z_-]{20}

# Pipeline job token
(?i)CI_JOB_TOKEN\s*[:=]\s*['"]?[0-9a-zA-Z_-]{20,}

# Deploy token
(?i)gitlab_deploy_token\s*[:=]\s*['"]?[0-9a-zA-Z_-]{20,}
```

## Slack

```
# Bot / App / Webhook tokens
xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24,32}

# Legacy webhook URL
https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}
```

## Google / GCP

```
# GCP API key
AIza[0-9A-Za-z_-]{35}

# GCP service account JSON — anchor on the begin line
"type":\s*"service_account"

# GCP OAuth client ID
[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com
```

## Azure

```
# Storage account key (64 base64 chars)
(?i)AccountKey\s*=\s*[A-Za-z0-9+/=]{64,}

# Shared access signature
(?i)SharedAccessSignature=sr=[^&]+&sig=[A-Za-z0-9%]+&st=[^&]+
```

## Stripe

```
# Secret key (live)
sk_live_[0-9a-zA-Z]{24,}

# Secret key (test)
sk_test_[0-9a-zA-Z]{24,}

# Restricted key (live)
rk_live_[0-9a-zA-Z]{24,}

# Publishable key — safe but worth detecting to correlate
pk_live_[0-9a-zA-Z]{24,}
```

## Twilio

```
AC[a-z0-9]{32}                            # Account SID
SK[a-z0-9]{32}                            # API Key SID
```

## SendGrid

```
SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}
```

## Mailgun

```
key-[0-9a-f]{32}
```

## PayPal / Braintree

```
access_token\$(production|sandbox)\$[0-9a-z]{16}\$[0-9a-f]{32}
```

## Private Keys (Asymmetric)

```
# Generic begin-header
-----BEGIN (RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED) PRIVATE KEY-----

# SSH private key (common)
-----BEGIN OPENSSH PRIVATE KEY-----

# PGP / GPG private key
-----BEGIN PGP PRIVATE KEY BLOCK-----
```

Any `BEGIN ... PRIVATE KEY` header in a tracked file is an immediate
finding — even if claimed "test only".

## JWT-Signing Secrets

Generic high-entropy strings named like JWT secrets:

```
(?i)(jwt[_-]?(secret|key)|hmac[_-]?key|signing[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9+/=]{16,}['"]?
```

## Database Connection Strings

```
# PostgreSQL
postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\w+

# MySQL
mysql://[^:]+:[^@]+@[^/]+/\w+

# MongoDB
mongodb(\+srv)?://[^:]+:[^@]+@[^/]+/

# JDBC with password
jdbc:(mysql|postgresql|mariadb|sqlserver|oracle)://[^\s?]+\?.*password=[^&\s"']+
```

## Docker Hub / Container Registry

```
# Docker Hub access token
dckr_pat_[A-Za-z0-9_-]{27,}

# Generic registry auth
"auths":\s*{\s*"[^"]+":\s*{\s*"auth":\s*"[A-Za-z0-9+/=]+
```

## Heroku

```
(?i)heroku[_-]?(api[_-]?key|oauth[_-]?token)\s*[:=]\s*['"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]?
```

## Discord Bot Token

```
[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}
```

## OpenAI

```
sk-[A-Za-z0-9]{48}           # legacy
sk-proj-[A-Za-z0-9_-]{100,}  # project-scoped
```

## Anthropic

```
sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{90,}
```

---

## Generic High-Entropy Heuristics

When no provider-specific pattern matches but the string is suspicious:

```
# Long base64 assigned to a var named *secret*, *token*, *api*, *key*
(?i)(secret|token|api[_-]?key|password|passwd|pwd)\s*[:=]\s*['"]?[A-Za-z0-9+/=_-]{20,}['"]?

# Hex string 32/40/64 chars often = md5/sha1/sha256
(?i)(secret|key|hash|token|digest)\s*[:=]\s*['"]?[a-f0-9]{32,64}['"]?
```

Entropy-based detection is best left to `detect-secrets` or
`trufflehog entropy` — they weigh Shannon entropy more cleanly than a
regex can.

---

## Common Filenames That Surface Secrets

```
.env
.env.local, .env.production, .env.dev
settings.yml, config.yml, secrets.yml
credentials.json, service-account*.json
application.properties, application.yaml
database.yml
.netrc, .pgpass
id_rsa, id_dsa, id_ed25519, *.pem, *.ppk, *.pkcs12
.aws/credentials, .aws/config
.ssh/known_hosts (informational, not secret)
terraform.tfstate, terraform.tfstate.backup
.git-credentials, _auth
```

Add these to git-ignore templates and pre-commit hooks.

---

## Repository Locations to Audit

The source emphasises that secrets live outside obvious files:

- Git commit history (`git log -p` — secrets removed in a later commit
  still exist in older commits).
- Git tags and orphaned branches.
- Issue / Pull-Request descriptions and comments.
- CI/CD artifacts (build logs, artifact bundles, `.github/workflows`).
- Source maps (`.js.map`) shipped to production.
- `.bash_history` / `.zsh_history` accidentally deployed.
- Wayback Machine snapshots of `/swagger.json`, `/.git/config`, `/.env`.
- Pastebin / GitHub Gist searches: `site:github.com "targetname" "api-key"`.

---

## Exclusion / Allowlist

Save `.gitleaksignore` or equivalent for confirmed false positives:

```
# .gitleaksignore
# False positive: sample data in test fixtures
tests/fixtures/sample-credentials.json:aws-access-token:12
tests/fixtures/sample-credentials.json:aws-secret-key:14
```

Include a comment identifying WHY it's a false positive.

---

## Verification Step (Before Reporting)

For each match, verify:

1. Is the credential still active? Attempt a read-only API call:
   - AWS: `aws sts get-caller-identity` with the key env-vars set
   - GitHub: `curl -H "Authorization: token ghp_..." https://api.github.com/user`
   - Slack: `curl -H "Authorization: Bearer xoxb-..." https://slack.com/api/auth.test`
2. Is it from a test / sandbox account (false positive) or production?
3. Which commit introduced it? (`git blame` + `git log` on the file)
4. Is it still in a public branch, or only history? (either way, treat
   as leaked — assume it's been pulled and rotate.)

---

## Safety Notes

- Do NOT use the discovered credentials in any way beyond a single
  identity call to verify they're live. No bucket downloads, no
  privilege enumeration, no resource listing.
- Report to the tenant's security team immediately — rotation is urgent
  regardless of whether the repository is now private.
- When scanning git history, run locally or in a scratch CI job —
  pushing a bulk-rewrite of history after removing secrets still leaves
  them accessible to anyone with a prior clone.
