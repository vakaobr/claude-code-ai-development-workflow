---
name: executive-elevator-translation
description: "Bridge communication between the Engine Room (code/ADR) and the Penthouse (C-level strategy, OKRs, and business value)."
model: sonnet
metadata:
  version: 1.0.0
  category: executive-communication
---

# Software Architect Elevator: Penthouse-to-Engine Room

## Goal
Translate low-level technical decisions, architectural technical debt, or refactorings (Engine Room) into strategic business value, OKRs, and financial metrics (Penthouse).

## When to Use
- When writing executive summaries, business cases for major refactoring, or presenting technical plans to stakeholders.
- During Phase 3 (Design) or Phase 11 (Retrospective) to justify structural changes.

## When NOT to Use
- Routine code-level fixes, standard feature implementations, or internal team meetings.

## Authorization Check
- Confirm authorization to review strategic corporate goals, team OKRs, or cloud budget delta forecasts.

## Methodology
1. **Ride the Elevator**: Focus on the multi-tiered translation of a technical decision:
   - **Floor 1 (Engine Room - Code)**: Refactoring SQLAlchemy imports, implementing UoW, adding Sagas.
   - **Floor 5 (Engineering Lead - Delivery)**: Reducing build times, eliminating cyclic dependency, decoupling releases.
   - **Floor 10 (Divisional Director - Product)**: Accelerating Time-To-Market (TTM), reducing bugs, boosting feature agility.
   - **Floor 20 (Penthouse - Executive Board)**: Reducing hosting costs (FinOps), mitigating system-down risks, aligning with regulatory ESG goals.
2. **Draft Technical Memos**: Limit to five pages. Omit technical jargon (like POSIX history, abstract parser engines) unless directly tied to the selection criteria.
3. **Formulate ROI Metrics**: Map refactoring tasks directly to business objectives using simple math (e.g., "Moving from always-on instances to Serverless reduces monthly cloud waste by 40%").

## Output Format
Create a `TECHNICAL_MEMO_EXECUTIVE.md` containing:
- **Executive Summary**: 2-3 sentence strategic pitch.
- **The Elevator Map**: Clear translation from Engine Room to Penthouse.
- **Business Impact**: Cost-benefit analysis, TTM impact, and risk reduction matrix.

## Quality Check
- Ensure zero technical jargon leaks into the Penthouse summary.
- Every assertion must be testable: avoid words like "use caution" or "highly performant" without numbers or criteria.

## Common Issues
- Over-explaining technical implementation: remember, C-level sponsors care about risk, cost, and speed, not package names.
