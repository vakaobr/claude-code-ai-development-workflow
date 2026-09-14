---
name: saas-multi-tenant-isolation
description: "Audit and enforce strict security, data partitioning, and isolation boundaries for multi-tenant SaaS applications."
model: opus
metadata:
  version: 1.0.0
  category: saas-multi-tenancy
---

# Multi-Tenant SaaS Isolation Gates

## Goal
Enforce strict boundaries to prevent cross-tenant data leaks and noisy neighbor issues in pooled or siloed compute/storage systems.

## When to Use
- During architectural reviews of multi-tenant microservices or database queries.
- Before launching new APIs in a shared-compute environment.

## When NOT to Use
- Single-tenant on-premise application deployments.

## Authorization Check
- Confirm authorization to audit identity provider policies, DynamoDB leading keys, or IAM policies.

## Methodology
1. **Tenant Context Extraction**:
   - Intercept JWT or HTTP headers at the gateway/middleware layer to extract the verified `tenant_id` claim.
2. **Noisy Neighbor Shunting**:
   - Inject rate-limiting/throttling headers scoped per-tenant-tier (Basic vs Gold).
3. **Storage Partitioning**:
   - Pooled Storage: Enforce that all repository database queries contain a `tenant_id` filter.
   - Siloed Storage: Dynamically route database sessions based on the verified tenant context.
4. **Credential Scope Isolation**:
   - Implement runtime credential generation (e.g., AWS STS `AssumeRole` with scoped policy templates dynamically injecting the `tenant_id` as DynamoDB `LeadingKeys`).

## Output Format
Generate safe middleware templates or audited query classes:
- Return code examples showing tenant routing or JWT parsing.
- Produce `TENANT_ISOLATION_REPORT.md` listing potential risk spots where `tenant_id` isn't forced.

## Quality Check
- Ensure database queries never rely on developers "remembering" to append `tenant_id`; query layers must automatically inject it.
- Verify that tenant context cannot be altered or overwritten on downstream calls.

## Common Issues
- Latency in dynamic role-assuming: cache scoped temporary credentials locally with a secure TTL.
