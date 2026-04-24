---
name: container-hunter
description: "Audits container / Kubernetes / OpenShift deployments for privileged pods, permissive SecurityContexts (runAsRoot, allowPrivilegeEscalation, hostPath mounts, hostNetwork, hostPID), missing NetworkPolicies, missing resource limits, lax RBAC (cluster-admin bindings), and Dockerfile patterns that leak creds or use moving-tag base images. Uses AWS CLI read verbs for EKS / ECS inventory; reads Dockerfile / K8s YAML from already-cloned repos; does NOT kubectl apply or describe live pods (delegate to operator). Use when the target runs containers (EKS / ECS / OpenShift / self-hosted K8s); or when `gitlab-cicd-hunter` / `secrets-in-code-hunter` surface container configs. Produces findings with CWE-732 / CWE-276 mapping and NetworkPolicy + SecurityContext + RBAC-hardening remediation."
model: sonnet
allowed-tools: >
  Read, Grep, Glob, Write(path:.claude/planning/**),
  Bash(aws:iam get-*), Bash(aws:iam list-*),
  Bash(aws:iam simulate-principal-policy*),
  Bash(aws:s3api get-*), Bash(aws:s3api list-*),
  Bash(aws:s3api head-*),
  Bash(aws:ec2 describe-*),
  Bash(aws:rds describe-*),
  Bash(aws:lambda get-*), Bash(aws:lambda list-*),
  Bash(aws:cloudtrail lookup-events),
  Bash(aws:configservice describe-*),
  Bash(aws:sts get-caller-identity),
  Bash(jq:*), Bash(yq:*)
metadata:
  version: 1.0.0
  category: security-testing
  subcategory: cloud
  authorization_required: true
  tier: T3
  source_methodology: "Segurança e Testes em Ambientes de Containers e Imagens.md"
  service_affecting: false
  composed_from: []
---

# Container Hunter

## Goal

Audit container-based deployments (Docker, Kubernetes, OpenShift,
ECS) for misconfigurations that weaken isolation or enable
escape: privileged containers, permissive SecurityContexts
(runAsRoot, allowPrivilegeEscalation, hostPath mounts,
hostNetwork, hostPID), missing NetworkPolicies, missing resource
limits (DoS surface), lax RBAC (cluster-admin role bindings),
and Dockerfile patterns that leak credentials or use moving-tag
base images. Reads deployment artifacts (Dockerfile,
docker-compose.yml, Kubernetes YAML) from already-cloned
repositories + queries AWS / EKS / ECS inventory via read-only
APIs. Does NOT run `kubectl describe` or `kubectl exec` on live
clusters — delegates live-cluster inspection to the operator.
Implements OWASP API4:2019 + API9:2019 (container-specific) and
CIS Kubernetes Benchmark adjacencies.

## When to Use

- The target runs containers on EKS / ECS / OpenShift / self-
  hosted Kubernetes (confirmed by scope `asset_type:
  container_orchestrator` OR recon surfaces container
  artifacts).
- `gitlab-cicd-hunter` / `secrets-in-code-hunter` flagged
  Dockerfile or `docker-compose.yml` in repos.
- The orchestrator requests a container-posture sweep.
- Compliance driver (CIS K8s Benchmark, PCI, SOC 2).

## When NOT to Use

- For account-wide IAM posture — use `aws-iam-hunter`.
- For image-vulnerability scanning (CVEs in base images) — use
  a dedicated scanner (Trivy, Snyk Container) outside this
  skill; cross-reference for handoff.
- For live cluster exec / debug — operator-level action
  outside this skill's boundary.
- For non-container deployments (pure VMs, serverless, PaaS) —
  out of scope.
- Any asset not listed in `.claude/security-scope.yaml` or whose
  `testing_level` is not at least `passive`.

## Authorization Check (MANDATORY FIRST STEP)

Before ANY outbound activity:

1. Read `.claude/security-scope.yaml`. If the file doesn't exist
   or doesn't parse, halt and report.
2. Confirm the target appears in the `assets` list AND
   `testing_level` is at least `passive`.
3. For AWS EKS / ECS inventory queries, confirm
   `aws sts get-caller-identity` reports the audit-role
   principal.
4. Use ONLY read-only verbs (`describe-*`, `list-*`, `get-*`).
   NO `create`, `update`, `delete`, `run-task`. The tool profile
   blocks write AWS verbs; this skill must not attempt.
5. Kubernetes artifact analysis uses `yq` / `jq` on locally-
   cloned YAML. Live `kubectl` is NOT in the tool profile —
   delegate any live-cluster inspection to the operator.
6. Log the authorization check to
   `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log
   with status `running`.

## Inputs

The skill expects the caller to provide:

- `{issue}`: the planning folder name
- `{target}`: the AWS account ID or cluster identifier
- `{aws_profile}`: named AWS profile for EKS/ECS inventory
- `{repo_paths}`: paths to cloned repos containing Dockerfile /
  K8s YAML
- `{cluster_manifests}`: optional — path to exported cluster
  YAML manifests for deep analysis

## Methodology

### Phase 1: Container Inventory

1. **EKS cluster enumeration** [AWS Best Practices]

   Do: If scope includes EKS:
   ```bash
   aws eks list-clusters --profile {aws_profile}
   ```

   For each cluster:
   ```bash
   aws eks describe-cluster --name {cluster} --profile {aws_profile}
   ```

   Record cluster version, endpoint accessibility (public /
   private), logging config, encryption status.

   Vulnerable signal: Cluster version >6 months behind latest
   (unpatched CVEs); public endpoint without
   `resourcesVpcConfig.endpointPublicAccess: false`.

   Record:
   `.claude/planning/{issue}/container-inventory.md`.

2. **ECS cluster + task-definition enumeration**
   [AWS ECS Best Practices]

   Do:
   ```bash
   aws ecs list-clusters --profile {aws_profile}
   aws ecs list-task-definitions --profile {aws_profile}
   aws ecs describe-task-definition --task-definition {arn} --profile {aws_profile}
   ```

   For each task def, extract:
   - `privileged: true` (escape primitive)
   - `readonlyRootFilesystem: false` (allows in-container
     writes, persistence)
   - `user: "0" / "root"` (non-least-priv)
   - `essential: true` across all containers (blast radius)
   - Missing `memoryReservation` / `cpu` limits

   Record: Per-task findings.

### Phase 2: Dockerfile Audit

3. **Static Dockerfile review**
   [Bug Bounty Bootcamp, Ch 5]

   Do: For every `Dockerfile` in `{repo_paths}`:
   ```bash
   find {repo_paths} -name 'Dockerfile*' -type f
   ```

   Grep + manual review for:
   - `FROM ...:latest` or no-tag (moving target)
   - `FROM ...:{major}` (e.g., `node:18`) without a specific
     minor/patch (slightly better but still mobile)
   - `USER root` or missing `USER` directive entirely
   - `COPY . /app` (copies build context, may include
     `.git/`, `.env`)
   - Hardcoded secrets in ENV / ARG (grep for AKIA, api_key,
     etc.)
   - `RUN curl ... | sh` (supply-chain risk)
   - `--privileged` in buildargs (unusual, worth noting)

   Record: Per-Dockerfile findings.

4. **Docker-compose.yml audit**
   [OWASP API4:2019]

   Do: For every `docker-compose.yml`:
   ```bash
   find {repo_paths} -name 'docker-compose*.yml' -type f
   ```

   Parse with `yq` and flag services with:
   - `privileged: true`
   - `network_mode: host`
   - `pid: host`
   - `volumes: [/:/host]` or any `/` host-mount
   - `volumes: [/var/run/docker.sock:/var/run/docker.sock]`
     (container → host escape via Docker API)
   - `cap_add: [SYS_ADMIN, SYS_PTRACE, ...]`
   - Missing `deploy.resources.limits`
   - Hardcoded secrets in `environment` section

   Record: Per-service compose findings.

### Phase 3: Kubernetes / OpenShift YAML Audit

5. **Pod / Deployment SecurityContext**
   [CIS Kubernetes Benchmark]

   Do: For every `*.yaml` / `*.yml` in `{repo_paths}` and
   `{cluster_manifests}` containing Kubernetes resources:
   ```bash
   find . \( -name '*.yaml' -o -name '*.yml' \) | \
     xargs yq eval 'select(.kind == "Pod" or .kind == "Deployment" or .kind == "DaemonSet" or .kind == "StatefulSet")' -
   ```

   For each workload, check `spec.template.spec.securityContext`
   and `spec.template.spec.containers[].securityContext`:
   - `privileged: true` — CRITICAL (full host access)
   - `allowPrivilegeEscalation: true` or missing (default) —
     allows setuid binaries
   - `runAsNonRoot: false` or missing — may run as root
   - `runAsUser: 0` — explicit root
   - `readOnlyRootFilesystem: false` — writable rootfs
   - `capabilities.add: [SYS_ADMIN, NET_ADMIN, SYS_PTRACE, ...]`
   - `hostPID: true`, `hostIPC: true`, `hostNetwork: true`
   - `volumes: [{hostPath: {path: "/"}}]` — host-root mount

   Vulnerable signal: Any of the above on pods that aren't
   intentionally privileged (e.g., node-agents, CNI pods).

   Record: Per-workload findings.

6. **RBAC review** [CIS Benchmark 5.1]

   Do: For ClusterRoleBindings / RoleBindings in YAML:
   ```bash
   find . -name '*.yaml' | xargs yq eval 'select(.kind == "ClusterRoleBinding" or .kind == "RoleBinding")' -
   ```

   Flag bindings that:
   - Reference the `cluster-admin` role bound to service
     accounts or user groups beyond the break-glass identity
   - Bind `system:masters` group to anything
   - Grant `*` on `*` (wildcard + wildcard)
   - Grant `pods/exec` / `pods/portforward` to service
     accounts that shouldn't need live debugging

   Record: Per-binding findings.

7. **NetworkPolicy coverage** [CIS Benchmark 5.3]

   Do: Check whether every namespace with workloads has a
   NetworkPolicy:
   ```bash
   # Count namespaces
   find . -name '*.yaml' | xargs yq eval 'select(.kind == "Namespace") | .metadata.name' - | sort -u > /tmp/ns-list

   # Count NetworkPolicies per namespace
   find . -name '*.yaml' | xargs yq eval 'select(.kind == "NetworkPolicy") | .metadata.namespace' - | sort | uniq -c
   ```

   Vulnerable signal: Namespaces with workloads but no
   NetworkPolicy (default-deny not enforced → pods can
   communicate freely cross-namespace).

   Record: Per-namespace NetworkPolicy status.

### Phase 4: Resource Limits and DoS Surface

8. **Missing resource limits per workload** [OWASP API4:2019]

   Do: For each Pod / Deployment, check
   `spec.template.spec.containers[].resources`:
   - Presence of `limits.cpu` AND `limits.memory`
   - Presence of `requests.cpu` AND `requests.memory`

   Vulnerable signal: Missing limits means a single pod can
   consume all node CPU/memory → DoS for other workloads on
   the same node.

   Record: Per-container limit-status matrix.

9. **Missing probes** [CIS Kubernetes Benchmark]

   Do: Check for `livenessProbe` and `readinessProbe` on
   every container. Missing probes don't directly create
   vulnerability but indicate incomplete deployment hygiene
   (crashed / zombie pods may serve stale responses).

   Record: Medium-severity hygiene findings.

### Phase 5: Image Registry and Supply Chain

10. **Image reference audit**
    [Supply chain security]

    Do: For every `image:` field in Dockerfile /
    compose / K8s:
    - Is it pulled from a public registry (Docker Hub,
      Quay.io)?
    - Is it from a private / org registry?
    - Is the tag pinned (`image:1.2.3-sha256:...`) or moving
      (`image:latest`, `image:stable`)?
    - Is image-signature verification configured
      (Notary / cosign / sigstore)?

    Vulnerable signal: Moving tags in production + no
    signature verification = supply-chain attack surface.

    Record: Per-image risk matrix.

11. **Image-registry credentials in code**
    [Bug Bounty Bootcamp, Ch 5]

    Do: Cross-reference `secrets-in-code-hunter` output for
    any registry credentials (Docker Hub tokens, AWS ECR
    authentication tokens, GitHub Container Registry tokens)
    in repos. Image-registry write access is a critical supply-
    chain vector.

## Payload Library

No payloads — configuration audit. Key analysis patterns:

- **SecurityContext dangerous flags**: `privileged`,
  `allowPrivilegeEscalation`, `runAsUser: 0`, `hostPath: /`,
  `hostNetwork: true`, `hostPID: true`, `hostIPC: true`
- **Capability allowlist**: dangerous caps (`SYS_ADMIN`,
  `SYS_PTRACE`, `NET_ADMIN`, `DAC_READ_SEARCH`)
- **RBAC patterns**: `cluster-admin` bindings, `*` verbs on
  `*` resources, `pods/exec` grants
- **Dockerfile anti-patterns**: `:latest`, `USER root`,
  `docker.sock` mounts, bare `RUN curl | sh`
- **Resource-limit checklists**: presence/absence patterns

## Output Format

Findings append to `.claude/planning/{issue}/SECURITY_AUDIT.md` per
the schema in `.claude/skills/_shared/finding-schema.md`.

Specific to this skill:

- **CWE**: CWE-732 (permission assignment — privileged
  containers). CWE-276 (Incorrect Default Permissions — missing
  SecurityContext). CWE-250 (Execution with Unnecessary
  Privileges — runAsRoot). CWE-798 for hardcoded creds in
  Dockerfiles.
- **OWASP**: For APIs, API4:2019 (Resource Consumption) for
  missing limits. API7:2019 / API8:2023 (Security
  Misconfiguration) for SecurityContext. A05:2021.
- **CVSS vectors**: privileged container on production cluster
  — `AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` (requires initial
  container access but full escape). hostPath / socket mount
  — similar. cluster-admin bound to SA — same. Missing
  NetworkPolicy — lower severity unless combined with breach
  scenario.
- **Evidence**: the YAML excerpt with the problematic setting,
  the resource name + namespace (for K8s) or task-definition
  ARN (for ECS), and a note on whether the setting is
  intentional vs accidental.
- **Remediation framing**: platform / SRE engineer + devops.
  Include:
  - SecurityContext snippets — `runAsNonRoot: true`,
    `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem:
    true`, `capabilities.drop: [ALL]`
  - Default-deny NetworkPolicy template per namespace
  - RBAC audit — `kubectl auth can-i --list` for each SA;
    remove cluster-admin where not needed
  - Dockerfile hardening — pin tags, use distroless base images,
    non-root USER, COPY only what's needed (not `.`)
  - Image-signature verification (cosign + Sigstore)
  - Container-runtime hardening: PodSecurity admission,
    OPA Gatekeeper / Kyverno policies

The skill also updates:

- `.claude/planning/{issue}/STATUS.md` — its row under Phase 7: Security
- `.claude/planning/{issue}/SECURITY_AUDIT.md` Skills Run Log

## Quality Check (Self-Review)

Before marking complete, verify:

- [ ] Every workload (Pod / Deployment / DaemonSet) has a
      SecurityContext status row
- [ ] Every Dockerfile was reviewed against the 8-item
      anti-pattern checklist
- [ ] RBAC review covered every ClusterRoleBinding +
      RoleBinding in the manifests
- [ ] NetworkPolicy coverage gaps are quantified (N namespaces
      without policies)
- [ ] No live-cluster `kubectl` calls were attempted — only
      YAML / AWS CLI
- [ ] No AWS write verb was executed
- [ ] Image-registry credentials discovered via
      `secrets-in-code-hunter` handoff are cross-referenced
- [ ] Skills Run Log row updated from `running` to `complete` or
      `halted:{reason}`

## Common Issues

- **Intentionally-privileged system pods**: CNI (Calico,
  Flannel), node-exporters, logging agents often NEED
  privileged: true or hostPath mounts. Distinguish "system
  infra" from "app workloads" by namespace (`kube-system`,
  `calico-system`, etc.) and suppress findings for those
  unless the namespace is unusual.

- **Missing SecurityContext = default "permissive"**: Kubernetes
  pods without explicit SecurityContext inherit permissive
  defaults (runAsRoot, etc.). Missing = vulnerable. This is
  subtle; file findings for absent sections, not just for
  explicit bad settings.

- **Dev vs prod clusters**: `dev` / `staging` clusters may have
  relaxed settings intentionally. Confirm environment before
  filing severity. However: even dev can be a pivot if
  networked to prod.

- **Rolled manifests vs Helm charts**: If the repo uses Helm,
  the YAML in the repo is a template; actual deployed values
  depend on the `values.yaml`. Audit both the template AND the
  values; mismatches are common.

- **Operator / CRD-managed resources**: Some resources (Kafka
  clusters via Strimzi, databases via CRDs) have their own
  SecurityContext at the operator level. The Pod-level YAML
  may look permissive because the operator sets securityContext
  dynamically. Check operator configuration if available.

- **Base-image CVE scope creep**: Users often expect this skill
  to scan base-image CVEs. It doesn't — CVE scanning is a
  dedicated tool's job (Trivy, Snyk). This skill flags config
  issues; file a gap to Trivy if base-image scanning is
  desired.

- **AWS IAM roles for service accounts (IRSA)**: EKS-specific —
  a pod can assume an IAM role via OIDC. If the SA annotation
  grants a role with broad permissions, pod compromise →
  cloud takeover. Cross-reference `aws-iam-hunter` for IRSA
  role audits.

## References

External:
- CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes
- Kubernetes Pod Security Standards:
  https://kubernetes.io/docs/concepts/security/pod-security-standards/
- OWASP Docker Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
- CWE-250: https://cwe.mitre.org/data/definitions/250.html
- OWASP API Security Top 10 (API4:2019, API7:2019, API9:2019)

## Source Methodology

Converted from:
`pentest-agent-development/notebooklm-notes/Segurança e Testes em Ambientes de Containers e Imagens.md`

Grounded in:
- Hacking APIs, Ch 5 (Infrastructure)
- OWASP API Security Top 10 (API4, API7, API9)
- Bug Bounty Bootcamp, Ch 5 + Ch 15
- CIS Kubernetes Benchmark
- OWASP Docker / Kubernetes cheat sheets

Conversion date: 2026-04-24
Conversion prompt version: 1.0
