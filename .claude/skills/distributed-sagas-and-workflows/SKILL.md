---
name: distributed-sagas-and-workflows
description: "Design and implement transactional consistency across distributed services using Orchestrated or Choreographed Saga patterns."
model: opus
metadata:
  version: 1.0.0
  category: distributed-systems
---

# Distributed Sagas & Event-Driven Workflows

## Goal
Implement atomic distributed transactions and compensation sequences across microservice boundaries without tight temporal coupling.

## When to Use
- When a business process spans multiple services (e.g., order booking, payment, stock assignment) and needs eventual consistency.
- When two-phase commits (2PC) degrade performance and scalability.

## When NOT to Use
- Within a single bounded context or monolith where database transactions can be utilized natively.

## Authorization Check
- Ensure permission to edit inter-service schemas, messaging broker pipelines (Kafka, RabbitMQ), and service code.

## Methodology
1. **Saga Orchestration**:
   - Define a single master manager service (Orchestrator) that dispatches commands to worker services.
   - Maintain the saga state machine (Initialized, Pending, Succeeded, Compensating, Aborted).
2. **Saga Choreography**:
   - Have services react to events published on a messaging channel (pub/sub), passing execution onward without a central driver.
3. **Compensation Logic**:
   - For every forward action (e.g., `reserve_stock`), write a corresponding, idempotent compensation action (e.g., `release_stock`) that runs if a downstream step fails.
4. **Transactional Outbox Pattern**:
   - Avoid double-writing (writing to database and publishing to queue simultaneously). Save events to an `outbox` table within the same DB transaction, and have a separate relay process publish them.

## Output Format
Scaffold saga templates:
- State machine configs or code blocks.
- Compensating action endpoints and outbox database schemas.

## Quality Check
- Verify that all compensation handlers are completely **idempotent** (can be called multiple times safely).
- Ensure **Correlation IDs** are injected into all messages and events to track execution.

## Common Issues
- Circular event triggers in Choreography: solve by mapping event paths clearly and refactoring complex flows into Orchestrated Sagas.
