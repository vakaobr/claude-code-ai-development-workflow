# signatures — gitlab-cicd-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia de Segurança e Auditoria em Pipelines CI_CD GitLab.md` (Section 3: DETECTION SIGNALS) + community `.gitlab-ci.yml` anti-patterns.

Detection signals scoped to GitLab-specific CI/CD misconfiguration.
For generic secret-format regexes (AWS, Slack, JWT, etc.), see
`secrets-in-code-hunter/references/signatures.md`.

---

## 1. Exposed CI/CD Configuration Files

Grep the repository tree (and historical commits) for:

```
\.gitlab-ci\.yml$
\.gitlab-ci-[^/]+\.yml$            # per-stage / per-env variants
\.gitlab/ci/                       # GitLab-CI include directory
Jenkinsfile                         # mixed-stack repos
docker-compose(\.[^.]+)*\.ya?ml$
package\.json$                      # npm build scripts
Dockerfile(\.[^.]*)?$
terraform\.tfstate$                 # IaC state with secrets
terraform\.tfvars$                  # variable overrides (often secrets)
```

A public repo containing `terraform.tfstate` is immediately a finding —
state files contain full resource inventories and sometimes secrets.

---

## 2. Insecure `.gitlab-ci.yml` Patterns

### 2a. Hardcoded secrets in variables

```yaml
# RED FLAG — variables are LOGGED in job output unless masked
variables:
  DB_PASSWORD: "s3cret_password"         # literal value in YAML
  AWS_SECRET_ACCESS_KEY: "wJalrXUt..."
  API_TOKEN: "ghp_literalToken"
```

Regex to grep:

```
^\s*(?i)(password|secret|token|key|api[_-]?key|private[_-]?key)\s*:\s*["']?[A-Za-z0-9/+=_-]{12,}["']?
```

### 2b. Privileged runners

```yaml
# RED FLAG — container escape surface
image: docker:20
services:
  - docker:20-dind
variables:
  DOCKER_TLS_CERTDIR: ""           # disables TLS → plaintext Docker socket
  DOCKER_HOST: tcp://docker:2375   # exposed daemon on network
```

Anti-pattern: pipelines running builds in "privileged" mode or mounting
the host Docker socket.

```
# Grep patterns:
privileged:\s*true
docker:\d+-dind
DOCKER_HOST:\s*tcp://[^:]+:2375
/var/run/docker\.sock                  # bind-mount of host socket
```

### 2c. Hardcoded registry credentials in `auths`

```yaml
# RED FLAG
before_script:
  - echo "$REGISTRY_AUTH_CONFIG" > ~/.docker/config.json
```

Where `$REGISTRY_AUTH_CONFIG` is set to a literal JSON containing base64
credentials (NOT masked).

### 2d. `when: manual` on destructive jobs without approvals

```yaml
# RED FLAG — any developer can trigger
deploy_prod:
  stage: deploy
  when: manual                     # no `protected: true`, no approvers defined
  script:
    - ./deploy.sh prod
```

Check whether `protected: true` AND a `rules:` gate is present.

### 2e. Arbitrary-branch triggers

```yaml
# RED FLAG — any push to any branch can deploy
deploy_prod:
  script: ./deploy.sh prod
  only:
    - pushes                       # not restricted to main
```

Or missing `only:` / `rules:` entirely — default is ALL branches.

### 2f. Submodule-spoofing / trigger-token leakage

```yaml
# RED FLAG — trigger token in plain config
trigger_downstream:
  trigger:
    project: group/other-project
    strategy: depend
  variables:
    CI_JOB_TOKEN: $CI_JOB_TOKEN    # token exposed in LOGS
```

Grep for: `CI_JOB_TOKEN` outside of a masked variable reference.

---

## 3. Exposed `.git` Directories (Server-Side)

Probe production hosts for:

```
/.git/
/.git/config
/.git/HEAD
/.git/index
/.git/logs/HEAD
/.gitignore                         # sometimes reveals what was committed
/.git-credentials
```

Tools:

```bash
# gitdumper — reconstruct repo from exposed .git
bash gitdumper.sh https://target.example/.git/ /tmp/restored

# git-ls-remote check
git ls-remote https://target.example/.git/ 2>/dev/null
```

---

## 4. Environment Files Accidentally Deployed

```
/.env
/.env.local
/.env.production
/.env.dev
/.env.backup
/env.js                             # SPA bundles env as JS
/config.js
/settings.json
```

Regex to grep for likely `.env` contents when fetched:

```
^[A-Z_][A-Z0-9_]*=[A-Za-z0-9/+=_"'-]{12,}$
```

---

## 5. Pipeline / Job Artifacts

Check for publicly accessible artifact URLs:

```
/-/jobs/\d+/artifacts/
/-/jobs/\d+/artifacts/browse/
/-/jobs/\d+/artifacts/raw/
/-/jobs/\d+/artifacts/download
```

Per-project: `https://gitlab.example/group/project/-/jobs/12345/artifacts/browse/`.

Artifacts often contain build logs with temporary tokens, compiled
binaries with embedded secrets, or test fixtures with sample data.

---

## 6. Webhook SSRF

GitLab webhooks that forward user-supplied URLs. Check the project's
hooks configuration:

```
/api/v4/projects/:id/hooks
```

Hooks for issues, merge requests, push events trigger outbound requests
from the GitLab runner. A webhook URL pointing at
`http://internal-admin:8080/restart` is an immediate SSRF primitive.

---

## 7. Developer Comments Revealing Technical Debt / Secrets

Grep source files:

```
//\s*(?i)(todo|fixme|xxx|hack|note)[:\s].*(?i)(password|secret|token|key|api|auth|credential)
#\s*(?i)(todo|fixme|xxx|hack)[:\s].*(?i)(password|secret|token|key|api|auth|credential)
<!--\s*(?i)(todo|fixme|xxx).*-->
```

Example from a real finding:

```python
# TODO: replace hardcoded password before release
DB_PASSWORD = "temppass123"
```

---

## 8. Common DevOps History Leaks

```
.bash_history
.zsh_history
.psql_history
.mysql_history
.rediscli_history
.lesshst
.viminfo
```

Grep for entries like:

```
curl -H "Authorization: Bearer [A-Za-z0-9]{20,}"
export (AWS_SECRET_ACCESS_KEY|SLACK_TOKEN)=
ssh -i /tmp/key
kubectl config set-credentials
```

---

## 9. `.well-known/security.txt` / Contact

Positive signal (not a vulnerability) — indicates a mature security
posture. Absence is a minor observation, not a finding.

```
/.well-known/security.txt
```

---

## 10. GitLab-Specific API Probes (Read-Only)

Enumerate project metadata via the public API (requires no auth for
public projects):

```bash
# Project list and visibility
curl "https://gitlab.example/api/v4/projects?visibility=public"

# CI/CD variables (REQUIRES token; shown here for context)
curl -H "PRIVATE-TOKEN: $TOKEN" \
     "https://gitlab.example/api/v4/projects/123/variables"

# Pipelines + jobs
curl "https://gitlab.example/api/v4/projects/123/pipelines?status=success"
```

---

## Quick Sweep Command

```bash
# Grep the working tree for obvious anti-patterns
grep -rnE "(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{16,}" \
     --include="*.yml" --include="*.yaml" --include=".env*" --include="*.tfvars"

# Scan for privileged docker
grep -rn "privileged:\s*true\|docker:.*-dind\|/var/run/docker\.sock" .gitlab-ci.yml

# Scan commit history for removed secrets
git log --all -p -S "AKIA" | head -200
git log --all --oneline -S "SECRET_KEY"
```

---

## Safety Notes

- These regexes over-match intentionally; verify each hit manually
  before reporting.
- For GitLab API endpoints that require authentication, only use a
  token scoped to read-only access (`read_api` / `read_repository`);
  do NOT use a `Maintainer`+ token for a scan.
- Report findings to the tenant's security + DevOps teams in parallel
  — rotating a live pipeline-token while a deploy is in-flight can
  break production.
