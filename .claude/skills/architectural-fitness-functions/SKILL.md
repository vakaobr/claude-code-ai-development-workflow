---
name: architectural-fitness-functions
description: "Turn architectural guardrails into executable, automated test gates (ArchUnit, metrics, license scans)."
model: sonnet
metadata:
  version: 1.0.0
  category: evolutionary-architecture
---

# Automated Architectural Fitness Functions

## Goal
Configure automated, continuous tests that guard architecture rules, boundary interfaces, and package dependency rules against code rot and decay.

## When to Use
- Setting up a new repository, bootstrapping a framework, or auditing layer violations (e.g., UI directly querying Database).
- Restricting import violations in Onion, Hexagonal, or Layered styles.

## When NOT to Use
- Small, single-purpose micro-repos or legacy codebases with no test framework maturity.

## Authorization Check
- Verify that you have permissions to write tests under the `tests/` directory and configure CI pipeline steps.

## Methodology
1. **Layer Boundary Verification**:
   - Implement **ArchUnit (Java)** or **NetArchTest (.NET)** or **import-linter (Python)** rules.
   - Define a rule asserting that code in the `domain` packages must not import or depend on packages in `adapters` or `entrypoints`.
2. **Annotation Rules**:
   - Assert that all classes extending a base model must be marked with specific metadata annotations (e.g., `@Entity`).
3. **Vulnerability & Supply Chain Gates**:
   - Configure a linter/scanner (like TruffleHog, Black Duck, or dependency-check) as a pre-commit or CI build step.
   - Assert license compliance: fail the build if a new dependency updates to an unapproved copyleft license.

## Output Format
- Executable test file (e.g., `tests/unit/test_architecture.py` or `tests/architecture_test.go`).
- CI/CD build stage config file (e.g., `.github/workflows/ci.yml`).

## Quality Check
- Test the fitness function by intentionally introducing an illegal import and verifying that the build fails.
- Document the exact "why" inside the test assertion message so developers know how to fix it.

## Common Issues
- Overly strict rules blocking hotfixes: establish an exclusion/bypass protocol with logged justification.
