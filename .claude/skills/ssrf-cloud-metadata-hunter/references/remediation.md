# remediation — ssrf-cloud-metadata-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Técnico_ Exploração de SSRF em Metadados de Nuvem.md` (Section 8: REMEDIATION)

The fix exists on two layers:
1. The application's SSRF surface (see `ssrf-hunter/references/remediation.md`).
2. The cloud tenant's metadata-service hardening.

This file focuses on (2).

---

## 1. AWS — Enforce IMDSv2 Only

IMDSv2 requires a session token via PUT, which simple SSRF primitives
cannot emit. Enforce it:

### Terraform

```hcl
resource "aws_instance" "app" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.medium"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"     # IMDSv2 only
    http_put_response_hop_limit = 1              # block containers from reaching IMDS
    instance_metadata_tags      = "disabled"
  }
}
```

`http_put_response_hop_limit = 1` is critical — it prevents containers
on the host (whose packets add a TTL hop) from reading IMDS at all.

### AWS CLI — modify an existing instance

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id i-0abcdef1234567890 \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

### Account-wide default (recommended)

```bash
aws ec2 modify-instance-metadata-defaults \
  --http-tokens required \
  --http-put-response-hop-limit 1 \
  --instance-metadata-tags disabled
```

### EKS / Fargate

For EKS worker nodes, set `metadataOptions` in the launch template of the
managed node group. For Fargate, IMDS is unreachable by default — no
extra config needed.

---

## 2. GCP — Disable v1beta1 and Require the Header

### Via gcloud

```bash
# Disable legacy metadata endpoints at instance creation:
gcloud compute instances create app-vm \
  --zone=us-central1-a \
  --metadata=disable-legacy-endpoints=TRUE
```

### For existing instances

```bash
gcloud compute instances add-metadata app-vm \
  --zone=us-central1-a \
  --metadata=disable-legacy-endpoints=TRUE
```

Once set, requests to `metadata.google.internal/computeMetadata/v1beta1/`
return 403. The v1 endpoint requires `Metadata-Flavor: Google` — simple
SSRF cannot set headers, so the vector collapses.

### GKE

Modern GKE clusters ship with Workload Identity — which removes the
service-account token from node metadata entirely. Migrate to Workload
Identity and treat the node-level metadata service as "no credentials
to steal":

```bash
gcloud container clusters update my-cluster \
  --workload-pool=my-project.svc.id.goog

# Then bind the Kubernetes SA to the GCP SA:
gcloud iam service-accounts add-iam-policy-binding \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:my-project.svc.id.goog[ns/sa]" \
  gcp-sa@my-project.iam.gserviceaccount.com
```

---

## 3. Azure — Managed Identity Best Practices

Azure IMDS already requires `Metadata: true`, which blocks simple SSRF.
The harder problem is the managed-identity access token — once issued,
it's a valid bearer credential for Azure Resource Manager.

### Terraform — use user-assigned identity with minimum scope

```hcl
resource "azurerm_user_assigned_identity" "app" {
  name                = "app-identity"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
}

resource "azurerm_role_assignment" "blob_reader" {
  principal_id         = azurerm_user_assigned_identity.app.principal_id
  role_definition_name = "Storage Blob Data Reader"    # NOT Contributor
  scope                = azurerm_storage_container.docs.resource_manager_id
}

resource "azurerm_linux_virtual_machine" "app" {
  # ...
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app.id]
  }
}
```

---

## 4. Defence in Depth — Egress Controls

Block application pods from reaching the metadata IP unless required.

### Kubernetes NetworkPolicy (EKS / GKE / AKS)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-imds
spec:
  podSelector: {}
  policyTypes: ["Egress"]
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32     # AWS, Azure, Alibaba
        - 100.100.200.200/32     # Alibaba China
        - 169.254.170.2/32       # AWS ECS task metadata
```

### AWS host-based iptables (for legacy self-managed workloads)

```bash
iptables -A OUTPUT -d 169.254.169.254 \
  -m owner --uid-owner app \
  -j DROP
```

### GCP Firewall egress rule

```bash
gcloud compute firewall-rules create deny-imds-egress \
  --direction=EGRESS \
  --destination-ranges=169.254.169.254/32 \
  --action=DENY \
  --rules=all \
  --priority=100
```

---

## 5. Least-Privilege IAM Roles

If the IMDS credentials are stolen, damage is bounded by the IAM role's
permissions. Audit and tighten:

```bash
# AWS
aws iam list-attached-role-policies --role-name <ROLE>
aws iam get-role-policy --role-name <ROLE> --policy-name <POLICY>

# Check "Resource": "*" — almost always over-broad
aws accessanalyzer create-analyzer --analyzer-name audit --type ACCOUNT
```

Replace `"Resource":"*"` with specific ARNs. Replace `"Action":"*"` with
a short allowlist. Remove `AdministratorAccess` from any instance role.

---

## 6. Monitoring / Detection

| Provider | Log source that surfaces IMDS credential use |
|----------|----------------------------------------------|
| AWS      | CloudTrail — `userIdentity.type == AssumedRole`; alert on unusual source IP / UA |
| AWS      | GuardDuty findings `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS` and `.OutsideAWS` |
| GCP      | Cloud Audit Logs — service-account activity tied to VM compute-default SA |
| Azure    | Azure AD sign-in logs for managed identities; alert on tokens used outside the VM's IP range |

Set an alert rule: "role credentials used from an IP not in my VPC range"
is almost always malicious.

---

## 7. Detection for Users of IMDSv1 (Still-Legacy Workloads)

Find remaining IMDSv1 callers before disabling:

```bash
# AWS CloudWatch metric: MetadataNoToken — calls to IMDS without session token
aws cloudwatch get-metric-statistics \
  --namespace AWS/EC2 \
  --metric-name MetadataNoToken \
  --dimensions Name=InstanceId,Value=i-xxxxx \
  --start-time 2026-04-01T00:00:00Z --end-time 2026-04-23T00:00:00Z \
  --period 3600 --statistics Sum
```

Non-zero values = instance still has IMDSv1 callers to fix before
flipping the switch.

---

## Provider Quick-Reference

| Provider | Minimum-acceptable hardening                                                     |
|----------|----------------------------------------------------------------------------------|
| AWS      | IMDSv2 required (`http_tokens = required`), hop-limit 1, least-privilege role    |
| GCP      | Legacy endpoints disabled, Workload Identity for GKE                             |
| Azure    | User-assigned managed identity with least-privilege RBAC role                    |
| OCI      | IMDSv2 required (`authorization=required`)                                       |
| K8s      | NetworkPolicy blocking egress to IMDS IPs; pods use IRSA / Workload Identity     |
