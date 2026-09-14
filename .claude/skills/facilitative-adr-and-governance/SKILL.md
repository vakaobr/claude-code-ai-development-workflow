---
name: facilitative-adr-and-governance
description: "Decentralize architectural decision-making using the Architecture Advice Process and record immutable ADRs."
model: sonnet
metadata:
  version: 1.0.0
  category: architecture-governance
---

# Facilitative Architecture Advice Process & ADRs

## Goal
Establish a collaborative and decentralized architectural decision registry using Dennis Bakke's Advice Process and lightweight Architectural Decision Records (ADRs).

## When to Use
- When introducing a significant technical change, tool, or library to a team.
- When teams are blocked by a centralized architecture review board.

## When NOT to Use
- Simple code implementation refactorings that don't impact system boundaries, interfaces, or cross-functional characteristics.

## Authorization Check
- Check that the proposed decision has consulted "affected parties" and "experts in the field" as per the advice process.

## Methodology
1. **Identify the Decision Initiator**: Anyone can initiate. The person who feels the need to decide is the Initiator and Decider.
2. **Seek Advice**: Consult the two required groups:
   - Affected Parties: People who will run, build, or live with the decision.
   - Experts: Individuals with experience or deep domain knowledge in the target technology.
3. **Draft the ADR**:
   - **ID and Title**: Format `ADR-NNN - short-name`.
   - **Status**: Mark as Draft or Proposed during advice seeking.
   - **Context**: Document the forces and constraints triggering this decision.
   - **Options Considered**: List alternatives with direct pros and cons (avoid complete rejections without reasons).
   - **Decision**: Bold/italicize the chosen route.
   - **Consequences**: Document the trade-offs and implications.
   - **Recorded Advice**: Append the specific advice offered by both groups.

## Output Format
A Markdown file at `.claude/planning/{issue}/03_ADR-{id}.md` conforming to standard Nygard or Harmel-Law layouts.

## Quality Check
- Verify that "Recorded Advice" has been explicitly populated.
- Ensure the author is named as the accountable decider.
- Check that the decision doesn't hide negative consequences or trade-offs.

## Common Issues
- Group deadlock or trying to achieve consensus: remind everyone that advice is NOT a vote. The decider holds the final authority to decide and commit.
