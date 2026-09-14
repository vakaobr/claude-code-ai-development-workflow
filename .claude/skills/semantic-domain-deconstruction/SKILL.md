---
name: semantic-domain-deconstruction
description: "Audit and deconstruct rigid code hierarchies, enums, and acoplated models to promote semantic clarity and extensibility."
model: opus
metadata:
  version: 1.0.0
  category: semantic-design
---

# Semantic Domain Deconstruction

## Goal
Audit and refactor complex, rigid codebases by deconstructing privileged binary pairs, removing deep inheritance hierarchies, and enforcing semantic truth in naming.

## When to Use
- When dealing with bloated classes, massive enum flags, or rigid database structures.
- When an API suffers from lack of "truth in advertising" (vague names, leaky abstractions).

## When NOT to Use
- Simple, flat utility libraries or pure infrastructure wrappers.

## Authorization Check
- Verify permission to refactor core domain models and public-facing APIs.

## Methodology
1. **Nouns & Verbs Audit**:
   - Critically evaluate word definitions. Reject vague terms like "ShortDescription" vs "LongDescription" or conflating "Customer", "User", and "Guest". Define boundaries explicitly.
2. **Composition over Inheritance**:
   - Locate deep inheritance trees. Refactor them using Python Protocols (PEP 544), ABCs, or composition with tag-based association.
3. **Deconstruct Binary Oppositions**:
   - Identify privileged oppositions (e.g., UI vs Database, Business vs Tech). Resolve the tension by creating clean, decoupled interfaces.
4. **Stateless curl Verification**:
   - Test semantic APIs using flat, deterministic, stateless endpoints that verify the model behaves as a pure mathematical concept.

## Output Format
- Markdown report mapping before-and-after domain taxonomy.
- Python code showing composition/Protocol replacements for deep inheritance.

## Quality Check
- Ensure no subclasses inherit behavior they don't use (Liskov violations).
- Verify all public API names represent real-world concepts in the ubiquitous language.

## Common Issues
- Rigid data schemas: replace deep tables hierarchies with flat models using flexible metadata tags.
