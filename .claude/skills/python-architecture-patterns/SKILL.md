---
name: python-architecture-patterns
description: "Refactor loosely-coupled, clean Onion Architecture in Python, implementing Repository, Service Layer, and Unit of Work patterns."
model: opus
metadata:
  version: 1.0.0
  category: architectural-patterns
---

# Python Architecture Patterns (Cosmic Python)

## Goal
Guide the user in refactoring Python codebases away from tight coupling to database frameworks (Django ORM, SQLAlchemy) or "distributed balls of mud" into Onion/Hexagonal clean architecture.

## When to Use
- When database models leak into the domain layer or presentation controllers.
- When business logic is tightly coupled to SQLAlchemy or Django dependencies.
- When writing unit tests is slow and complex due to database setup.

## When NOT to Use
- Simple CRUD scripts, small FastAPI prototypes, or single-file scripts where extra layers add unnecessary complexity.

## Authorization Check
- Confirm that the target codebase is Python and that refactoring is requested on specific business models or adapters.

## Methodology
1. **Domain Isolation**:
   - Extract domain business models into a pure `domain/model.py` containing pure dataclasses or POPOs (Plain Old Python Objects) with zero external imports (no SQLAlchemy, no Django).
   - Use Value Objects (dataclasses where equality is based on attributes) and Entities (where identity is persistent).
2. **Repository Pattern**:
   - Create an abstract port `AbstractRepository` (or Protocol) with `add(entity)` and `get(id)` methods.
   - Implement concrete adapter repositories (e.g., `SqlAlchemyRepository` or `DjangoRepository`) in `adapters/repository.py`.
3. **Service Layer**:
   - Write use-case handlers in `service_layer/services.py` that only accept primitive inputs (strings, ints) to keep dependencies clean.
4. **Unit of Work (UoW)**:
   - Implement an `AbstractUnitOfWork` context manager in `service_layer/unit_of_work.py` to handle atomic commits and rollbacks.

## Output Format
Generate Python file structures in a clean folder tree:
- `src/domain/model.py`
- `src/adapters/repository.py`
- `src/service_layer/unit_of_work.py`
- `src/service_layer/services.py`

## Quality Check
- Ensure `domain/model.py` has no external library imports (like SQLAlchemy, Flask, Django).
- Verify database sessions are managed exclusively inside the UoW's context manager.
- Verify tests are categorized under `unit/`, `integration/`, and `e2e/`.

## Common Issues
- Python Circular Imports: Solve by moving model registrations or mapping steps to adapters/orm.py and importing them during boot bootstrapping.
