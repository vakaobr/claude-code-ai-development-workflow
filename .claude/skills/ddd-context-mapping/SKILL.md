---
name: ddd-context-mapping
description: "Establish Bounded Contexts, construct Context Maps, and design Anticorruption Layers (ACL) between systems."
model: opus
metadata:
  version: 1.0.0
  category: domain-driven-design
---

# DDD Context Mapping & Anticorruption Layers

## Goal
Establish clean language boundaries between disparate subdomains and prevent models from leaking into each other using tactical patterns like Anticorruption Layers (ACL).

## When to Use
- When integrating a new microservice with a legacy monolith or a third-party API.
- When distinct teams have differing definitions for the same business term (e.g., "Customer" in Sales vs. "Customer" in Support).

## When NOT to Use
- Highly cohesive internal components sharing a single, unified Bounded Context.

## Authorization Check
- Confirm authorization to review system-wide architecture integration maps.

## Methodology
1. **Elicit Ubiquitous Language**: Document distinct terminology for each Bounded Context.
2. **Establish Relationships**: Define the team and model integration relation type on your **Context Map**:
   - **Partnership**: Co-developed, shared release cycles.
   - **Shared Kernel**: Shared database schema or common library code.
   - **Customer-Supplier**: Upstream controls the downstream delivery.
   - **Conformist**: Downstream conforms directly to upstream schemas.
   - **Anticorruption Layer (ACL)**: Downstream translates upstream data into its own clean domain.
   - **Open-Host Service (OHS)**: Upstream provides a stable, public API.
3. **Scaffold an Anticorruption Layer (ACL)**:
   - Create a service or class structure consisting of an Adapter (to call the external API) and a Translator (to convert raw external schemas into clean internal domain objects).

## Output Format
- A context map diagram specification (e.g., Mermaid.js code showing system dependencies).
- Python/Java class structures implementing the ACL patterns.

## Quality Check
- Ensure that external API client classes never leak directly into internal domain use cases.
- Verify that translating schemas doesn't trigger circular dependencies.

## Common Issues
- Model bleed: solve by maintaining strict boundary tests blocking internal code from instantiating external packages.
