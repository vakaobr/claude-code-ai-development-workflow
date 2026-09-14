---
name: sociotechnical-iceberg-analysis
description: "Apply systems thinking to debug complex incidents and sociotechnical issues using the Iceberg Model."
model: opus
metadata:
  version: 1.0.0
  category: systems-thinking
---

# Sociotechnical Iceberg Analysis & Systems Thinking

## Goal
Diagnose chronic system failures, bugs, or organizational friction by mapping issues across the four levels of the Systems Thinking Iceberg Model.

## When to Use
- When debugging recurring production incidents, Conway's Law issues, or team communication silos.
- During post-incident reviews or retrospectives (Phase 11).

## When NOT to Use
- Linear, simple bugs (e.g., simple syntax errors, typo fixes).

## Authorization Check
- Ensure access to historical incident logs, retrospectives, and team topology directories.

## Methodology
Decompose the issue using the **Iceberg Model**:
1. **Events (What just happened?)**: Document the symptoms, incident alerts, error logs, and immediate impact.
2. **Patterns (What has been happening over time?)**: Look for history. Have we seen this spike before? How often do these incidents occur?
3. **Structures (What is sustaining this behavior?)**: Analyze structural drivers. How are teams organized (Team Topologies)? How is code coupled? What are the communication loops (Conway's Law)? Is there a feedback loop delay?
4. **Mental Models (What values/beliefs support the structure?)**: Diagnose culture. What beliefs ("we must deploy fast at all costs", "testing is QA's job") are driving these structures?

## Output Format
Create a `SYSTEMS_THINKING_ICEBERG.md` analysis containing:
- **Iceberg Map**: Four levels structured with clear, documented interrelationships.
- **Feedback Loops**: Causal Loop Diagrams (Mermaid.js) showing reinforcing or balancing loops.
- **Leverage Points**: Specific, actionable suggestions where a small change in structure or mental model yields massive systemic improvement.

## Quality Check
- Verify that structural analysis includes both technical coupling AND organizational structures.
- Ensure leverage points are actionable and do not merely say "improve culture."

## Common Issues
- Blaming individuals: shift perspective from "who did it" to "what structural incentives allowed this to happen."
