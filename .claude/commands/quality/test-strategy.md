## Quality: Test Strategy & Setup

Design and implement a testing strategy for the project or a specific feature. Context: `$ARGUMENTS`

### Instructions

Auto-detect the project stack, evaluate current test coverage, and produce a comprehensive testing strategy with ready-to-use configuration.

### Step 1: Stack Detection & Current State

Scan for test infrastructure:

```
Test Runners:
- vitest.config.*    → Vitest (JS/TS)
- jest.config.*      → Jest (JS/TS)
- pytest.ini / pyproject.toml [tool.pytest]  → Pytest (Python)
- phpunit.xml        → PHPUnit (PHP)
- .rspec             → RSpec (Ruby)

E2E / Integration:
- playwright.config.* → Playwright
- cypress.config.*    → Cypress
- tests/e2e/          → E2E directory convention

Coverage:
- .nycrc / c8         → Istanbul/c8 (JS)
- .coveragerc         → Coverage.py (Python)
- phpunit.xml coverage → PHPUnit coverage
```

Report:
- Test runner: {detected or "none configured"}
- Current test count: {count}
- Current coverage: {percentage or "unknown"}
- Test directories: {paths}

### Step 2: Test Strategy Document

Produce a `TEST_STRATEGY.md`:

```markdown
# Test Strategy

## Testing Pyramid

```
         ╱  E2E  ╲         ← Few, slow, high confidence
        ╱──────────╲
       ╱ Integration ╲     ← Moderate count, test boundaries
      ╱────────────────╲
     ╱    Unit Tests     ╲  ← Many, fast, isolated
    ╱──────────────────────╲
```

## Acceptance Criteria (BDD)

Every feature's acceptance criteria are written as **Given / When / Then** (per the Quality Contract). These drive the tests below — each scenario maps to an integration or E2E test:
```gherkin
Scenario: {behavior}
  Given {initial context}
  When {action}
  Then {observable outcome}
```

## Layer Definitions

### Unit Tests
- **What**: Individual functions, classes, hooks, utilities
- **Isolation**: Mock all external dependencies
- **Speed**: < 10ms per test
- **Coverage target**: ≥ 90% lines (critical paths ≥ 95%) — per the **Quality Contract** (`CLAUDE.md`)
- **Naming**: `{module}.test.{ext}` co-located with source

### Integration Tests
- **What**: Module interactions, API endpoints, database queries
- **Isolation**: Real dependencies within the service, mock external services
- **Speed**: < 500ms per test
- **Coverage target**: All API endpoints, all database operations
- **Naming**: `{feature}.integration.test.{ext}` in `tests/integration/`

### E2E Tests
- **What**: Critical user journeys through the full system
- **Isolation**: Full stack running (can use test database)
- **Speed**: < 30s per test
- **Coverage target**: Top 5-10 user flows
- **Naming**: `{journey}.e2e.test.{ext}` in `tests/e2e/`

## What to Test (Priority Order)

1. **Business logic**: Domain rules, calculations, state transitions
2. **API contracts**: Request validation, response shapes, status codes
3. **Error paths**: Invalid input, network failures, auth failures
4. **Edge cases**: Empty collections, boundary values, concurrent access
5. **Security**: Auth bypass, injection, CSRF, rate limiting
6. **Data integrity**: Migrations, constraints, cascading operations
7. **User flows (E2E)**: Registration, checkout, core workflows

## What NOT to Test

- Framework internals (React rendering, ORM query building)
- Third-party library behavior
- Private implementation details (test behavior, not structure)
- CSS/styling (use visual regression tools if needed)
- Simple getters/setters without logic

## Test Quality Rules

- **Arrange-Act-Assert**: Every test has clear setup, action, and verification
- **One assertion concept per test**: Test one behavior (can have multiple asserts if testing one outcome)
- **Descriptive names**: `should return 404 when user not found` not `test1`
- **No test interdependence**: Tests run in any order, clean up after themselves
- **No logic in tests**: No if/else, loops, or complex setup — extract to helpers
- **Test behavior, not implementation**: Don't assert on internal state
- **Use factories/builders**: Not hardcoded test data
```

### Step 3: Configuration Generation

Based on detected stack, generate ready-to-use test configuration:

**JavaScript/TypeScript (Vitest):**
```typescript
// vitest.config.ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node', // or 'jsdom' for React
    include: ['src/**/*.test.{ts,tsx}'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      exclude: ['node_modules/', 'tests/fixtures/', '**/*.d.ts'],
      thresholds: {
        lines: 80,
        branches: 75,
        functions: 80,
        statements: 80,
      },
    },
    setupFiles: ['./tests/setup.ts'],
  },
});
```

**Python (Pytest):**
```toml
# pyproject.toml
[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
python_functions = ["test_*"]
addopts = "-v --strict-markers --tb=short -q"
markers = [
    "slow: marks tests as slow",
    "integration: marks integration tests",
    "e2e: marks end-to-end tests",
]

[tool.coverage.run]
source = ["src"]
omit = ["tests/*", "*/migrations/*"]

[tool.coverage.report]
fail_under = 80
show_missing = true
```

**PHP (PHPUnit):**
```xml
<!-- phpunit.xml -->
<phpunit bootstrap="vendor/autoload.php" colors="true" stopOnFailure="false">
    <testsuites>
        <testsuite name="Unit">
            <directory>tests/Unit</directory>
        </testsuite>
        <testsuite name="Integration">
            <directory>tests/Integration</directory>
        </testsuite>
    </testsuites>
    <coverage>
        <include>
            <directory>src</directory>
        </include>
        <report>
            <html outputDirectory="coverage"/>
            <text outputFile="php://stdout" showOnlySummary="true"/>
        </report>
    </coverage>
</phpunit>
```

### Step 4: Test Scaffolding

Generate example tests based on detected patterns:

- If API routes exist → generate API contract test examples
- If database models exist → generate repository test examples
- If React components exist → generate component test examples with Testing Library
- If CLI commands exist → generate command test examples
- If background jobs exist → generate job test examples

Each example should demonstrate:
- Proper setup/teardown
- Mocking strategy
- Assertion patterns
- Error case testing

### Step 5: CI Integration

Provide the test commands for CI pipeline:

```yaml
# Tests should run in this order (fail-fast):
1. Lint + Type Check      # Fastest, catches obvious issues
2. Unit Tests             # Fast, high coverage
3. Integration Tests      # Medium, test boundaries
4. E2E Tests              # Slow, high confidence (optional on PR, required on main)
5. Coverage Report        # Publish as PR comment or artifact
```

### Quality Gates
- Test runner is configured and working
- At least one example test per layer (unit, integration)
- Coverage thresholds are configured
- CI integration commands are specified
- Test naming convention is documented
- Factory/builder pattern demonstrated for test data
