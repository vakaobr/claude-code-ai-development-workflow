---
name: contract-first-api-evolution
description: "Design OpenAPI contracts first, manage API schemas, and prevent breaking API updates."
model: sonnet
metadata:
  version: 1.0.0
  category: api-lifecycle
---

# Contract-First API Evolution & Design

## Goal
Automate contract-first API development, ensuring that services remain decoupled, backward compatible, and verified using Consumer-Driven Contracts (CDC).

## When to Use
- When designing new endpoints or evolving existing REST/gRPC/GraphQL interfaces.
- Decoupling frontend and backend delivery streams.

## When NOT to Use
- Internal methods, private helper classes, or strictly monolithic local calls.

## Authorization Check
- Check that the target OpenAPI/AsyncAPI contract is owner-approved before publishing.

## Methodology
1. **Contract First**:
   - Draft OpenAPI or AsyncAPI specifications in YAML *before* writing controller code.
   - Use mock tools (e.g., Prism) to let consumers test the schema instantly.
2. **Breaking Change Audit**:
   - Run comparison checks during PR reviews (e.g., using `oasdiff` or `buf` for protobuf).
   - Flag breaking changes: removing fields, renaming attributes, or modifying content types.
3. **Consumer-Driven Contract Testing (CDC)**:
   - Configure **Pact** or equivalent CDC frameworks.
   - Let client teams write expected contract mocks, creating shared integration test suites.
4. **Deconstructed Versioning**:
   - Implement semantic versioning (Major version in URI, e.g., `/v1/`, Minor version passed dynamically via date-query parameter, e.g., `?version=2026-09-04`).

## Output Format
- Valid OpenAPI/AsyncAPI specification YAML file.
- CDC Pact test template.
- Compatibility audit log.

## Quality Check
- Verify the contract has zero syntax errors.
- Ensure that domain DB tables are NEVER exposed directly in API outputs; always translate through DTO (Data Transfer Objects) mapping layers.

## Common Issues
- Changing data types breaking clients: implement backward-compatible mapper adapters that transform incoming legacy formats.
