# remediation — gitlab-cicd-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia de Segurança e Auditoria em Pipelines CI_CD GitLab.md` (Section 8: REMEDIATION)

---

## 1. Use GitLab CI Masked + Protected Variables

Never embed secrets in `.gitlab-ci.yml`. Store them as masked variables
scoped to protected branches.

### Via UI

`Project > Settings > CI/CD > Variables > Add variable`:
- Key: `AWS_SECRET_ACCESS_KEY`
- Value: (paste)
- Type: `Variable` (not `File` unless binary)
- Environment scope: `production` (or `*` for all)
- **Protect variable**: YES (only available on protected branches/tags)
- **Mask variable**: YES (redacts from job logs; must be base64-safe,
  >= 8 chars)

### Via API

```bash
curl --request POST \
  --header "PRIVATE-TOKEN: $GL_ADMIN_TOKEN" \
  --form "key=AWS_SECRET_ACCESS_KEY" \
  --form "value=$SECRET_VALUE" \
  --form "protected=true" \
  --form "masked=true" \
  --form "environment_scope=production" \
  "https://gitlab.example/api/v4/projects/$PID/variables"
```

### Consume in `.gitlab-ci.yml`

```yaml
deploy_prod:
  stage: deploy
  script:
    - aws s3 sync ./dist s3://prod-bucket/
  only:
    refs: [main]
    variables:
      - $CI_COMMIT_REF_PROTECTED == "true"
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

---

## 2. Use External Secret Managers (Preferred)

Masked CI variables still live in GitLab's DB. For long-term and
cross-project secrets, fetch from HashiCorp Vault / AWS Secrets Manager
at job runtime.

### HashiCorp Vault via OIDC (GitLab 15.3+)

```yaml
deploy_prod:
  id_tokens:
    VAULT_TOKEN:
      aud: https://gitlab.example
  script:
    - |
      export VAULT_ADDR=https://vault.example
      export VAULT_TOKEN=$(vault write -field=token \
          auth/jwt/login role=gitlab-deploy jwt=$VAULT_TOKEN)
    - export DB_PASSWORD=$(vault kv get -field=password secret/prod/db)
    - ./deploy.sh
```

### AWS Secrets Manager via OIDC

```yaml
deploy_prod:
  id_tokens:
    AWS_TOKEN:
      aud: https://sts.amazonaws.com
  script:
    - CREDS=$(aws sts assume-role-with-web-identity \
          --role-arn "arn:aws:iam::123456789012:role/gitlab-deploy-prod" \
          --role-session-name "ci-$CI_JOB_ID" \
          --web-identity-token "$AWS_TOKEN" \
          --duration-seconds 900)
    - export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r '.Credentials.AccessKeyId')
    - export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r '.Credentials.SecretAccessKey')
    - export AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r '.Credentials.SessionToken')
    - aws s3 sync dist/ s3://prod-bucket/
```

Plus a matching IAM trust policy with the GitLab OIDC provider:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/gitlab.example" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "gitlab.example:sub": "project_path:mygroup/myrepo:ref_type:branch:ref:main"
      }
    }
  }]
}
```

---

## 3. Lock Down Runners

### Disable privileged mode

```toml
# /etc/gitlab-runner/config.toml
[[runners]]
  name = "app-builder"
  executor = "docker"
  [runners.docker]
    privileged = false
    volumes = ["/cache"]          # NOT /var/run/docker.sock
    disable_entrypoint_overwrite = true
    oom_kill_disable = false
```

### Use rootless builds

Replace Docker-in-Docker (DinD) with Kaniko / Buildah / img — they build
container images without a privileged daemon:

```yaml
build:
  image:
    name: gcr.io/kaniko-project/executor:v1.19.2-debug
    entrypoint: [""]
  script:
    - /kaniko/executor
        --context "${CI_PROJECT_DIR}"
        --dockerfile "${CI_PROJECT_DIR}/Dockerfile"
        --destination "${CI_REGISTRY_IMAGE}:${CI_COMMIT_SHA}"
```

### Separate runner pools

- Tag runners: `app-builds`, `infra-deploys`, `security-scans`.
- Protected-branch jobs run ONLY on protected runners (distinct
  hardware / isolation).

---

## 4. Protect Production Branches

`Settings > Repository > Protected branches`:
- Branch: `main`
- Allowed to merge: Maintainers
- Allowed to push: No one
- Allowed to force push: No one
- Code owner approval required: YES

Require merge-request approvals from CODEOWNERS:

```
# .gitlab/CODEOWNERS
/infra/         @sre-team
/billing/       @billing-team
*.tf            @sre-team @security
```

---

## 5. Pin Base Images and Rules

### Pin image tags (no `latest`)

```yaml
image: python:3.12.3-slim-bookworm@sha256:abc123...   # digest pin
```

### Pin all included templates

```yaml
include:
  - project: myorg/ci-templates
    file: /deploy.yml
    ref: v2.4.1                   # tag, not a moving branch
```

Moving `ref: main` means a surprise change to `ci-templates` can
invade your pipeline.

---

## 6. Integrate Security Scanners in the Pipeline

```yaml
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml
  - template: Security/DAST.gitlab-ci.yml          # dynamic, optional

variables:
  SAST_EXCLUDED_ANALYZERS: ""
  SECRET_DETECTION_HISTORIC_SCAN: "true"           # scan full git history
```

Fail the pipeline on high-severity findings:

```yaml
sast:
  allow_failure: false
```

---

## 7. Rotate Exposed Credentials

When a secret is found in history, rotating the secret is NON-OPTIONAL.
Removing the commit (`git filter-branch` / `git filter-repo`) does NOT
remove it from forks / prior clones.

```bash
# AWS — deactivate then delete
aws iam update-access-key --access-key-id AKIA... --status Inactive --user-name bot
aws iam delete-access-key --access-key-id AKIA... --user-name bot

# GitLab — revoke personal access token
curl -X POST -H "PRIVATE-TOKEN: $ADMIN" \
  "https://gitlab.example/api/v4/personal_access_tokens/$TOKEN_ID/revoke"

# Slack bot token — reinstall the app to rotate
# Heroku API key — heroku authorizations:revoke <ID>
```

---

## 8. Webhook SSRF Defense

- Store webhook destinations on an allowlist of target hosts.
- Reject webhook URLs whose hostname resolves to a private-IP range.
- Run webhook dispatches through an outbound proxy that enforces the
  allowlist.

```python
# Example: validate webhook URL before registering
from ipaddress import ip_address, ip_network
import socket
from urllib.parse import urlparse

PRIVATE_RANGES = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("169.254.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("::1/128"),
]

def validate_webhook_url(url: str) -> bool:
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return False
    try:
        ip = ip_address(socket.gethostbyname(p.hostname))
    except Exception:
        return False
    return not any(ip in r for r in PRIVATE_RANGES)
```

---

## 9. Remove `.git` from Production Webroots

```nginx
# Nginx
location ~ /\.git {
  deny all;
  return 404;
}
```

```apache
# Apache
<DirectoryMatch "/\.git">
  Require all denied
</DirectoryMatch>
```

Better: don't check `.git` into the deployed artifact at all (use a
CI-built tarball / container image as the deploy artifact).

---

## 10. Audit and Monitoring

- GitLab Admin Area > Audit Events — alert on:
  - `Project access granted (Owner)`
  - `Variable created/updated`
  - `Runner registered`
  - `Protected branch removed`
- Forward audit logs to the central SIEM.
- Alert on unusual `docker pull` / `s3:GetObject` patterns post-deploy.

---

## Framework Quick-Reference

| Need                                   | GitLab-native solution                                   |
|----------------------------------------|----------------------------------------------------------|
| Secret storage                         | Masked + protected CI variables; Vault / SecretsManager via OIDC |
| Secret removal                         | ROTATE (not just rewrite history) + run `Secret Detection` pipeline |
| Privileged builds                      | Kaniko / Buildah / img (rootless)                        |
| Branch protection                      | Protected branches + CODEOWNERS + approval rules         |
| Runner isolation                       | Dedicated protected runners, tagged per environment      |
| Pipeline templates                     | Pin to tag, not branch                                   |
| Webhook SSRF                           | Allowlist destinations + private-range check             |
| Supply-chain                           | GitLab Dependency Scanning + License Compliance          |

---

## 11. Regression Tests / CI Checks

```bash
# Run in a lint job to catch anti-patterns
.gitlab-ci-lint:
  stage: lint
  script:
    - |
      # Fail if any job has privileged: true
      yq '.[] | select(.services[]?.privileged == true)' .gitlab-ci.yml && exit 1 || true
    - |
      # Fail on hardcoded-looking secrets
      grep -E '(?i)(password|secret|token|api[_-]?key)\s*:\s*["][^$][^"]+["]' .gitlab-ci.yml \
        && echo "Hardcoded-looking secret in .gitlab-ci.yml" && exit 1 || true
    - |
      # Fail on unpinned images
      grep -E '^\s*image:\s+[^:]+:(latest|main|master)\s*$' .gitlab-ci.yml \
        && echo "Unpinned image tag" && exit 1 || true
```
