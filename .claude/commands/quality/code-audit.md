## Quality: Code Quality Audit

Comprehensive code quality analysis across the codebase. Context: `$ARGUMENTS`

### Instructions

Perform a full code quality audit of the project (or the specified area). This command auto-detects the language/framework stack and applies the appropriate quality standards.

### Step 1: Stack Detection

Scan the project root and identify:

```
Detect:
- package.json      → Node.js (check for react, next, vue, angular, etc.)
- tsconfig.json     → TypeScript
- composer.json     → PHP
- pyproject.toml    → Python (check for django, fastapi, flask, etc.)
- requirements.txt  → Python (fallback)
- Cargo.toml        → Rust
- go.mod            → Go
- Gemfile           → Ruby
- *.tf / *.tfvars   → Terraform
- Dockerfile        → Container workload
- serverless.yml    → Serverless Framework
- .github/workflows → GitHub Actions CI
- .gitlab-ci.yml    → GitLab CI
```

Report the detected stack before proceeding.

### Step 2: Static Analysis

Run ALL available quality tools based on detected stack:

**JavaScript/TypeScript:**
```bash
npx eslint . --max-warnings 0       # Lint
npx tsc --noEmit                     # Type check (if TS)
npx prettier --check .               # Format check
```

**Python:**
```bash
ruff check .                         # Lint (or flake8)
ruff format --check .                # Format check (or black --check)
mypy . --strict                      # Type check (or pyright)
```

**PHP:**
```bash
./vendor/bin/phpstan analyse -l max  # Static analysis
./vendor/bin/phpcs                   # Code style (PSR-12)
./vendor/bin/php-cs-fixer fix --dry-run --diff  # Format check
```

**Terraform:**
```bash
terraform fmt -check -recursive      # Format
terraform validate                   # Validate
tflint --recursive                   # Lint
```

**General:**
```bash
# Dependency vulnerabilities
npm audit / pip audit / composer audit

# Secret detection
grep -rn "AKIA\|sk-\|password\s*=\|secret\s*=" --include="*.{ts,js,py,php,tf,env}" .

# TODO/FIXME inventory
grep -rn "TODO\|FIXME\|HACK\|XXX" --include="*.{ts,js,py,php,tf}" .
```

### Step 3: Code Metrics

Calculate and report:

> Targets below come from the **Quality Contract** (canonical in `CLAUDE.md`) — do not restate different numbers here.

| Metric | Target | How |
|--------|--------|-----|
| Test coverage | ≥ 90% (critical paths ≥ 95%) — per Quality Contract | Coverage tool output |
| Cognitive complexity | frontend ≤ 12 · backend ≤ 15 · engines ≤ 25 — per Quality Contract | Static analysis (eslint `complexity`, ruff `C901`, PHPMD, SonarQube) |
| Acceptance criteria | BDD Given/When/Then present for each feature | Spec/test review |
| Architecture | frontend MVVM · backend Hexagonal (ports & adapters) | Architecture review (Step 4) |
| File length | < 300 lines | `wc -l` on source files |
| Function length | < 30 lines | Static analysis |
| Dependency count | Minimize | Package manifest |
| Duplicate code | < 3% | Detection tool or manual scan |
| TODO/FIXME count | Tracked, not growing | grep count |
| Outdated dependencies | < 10% of total | `npm outdated` / equivalent |

### Step 4: Architecture Quality

Evaluate:

- [ ] **Separation of concerns**: Are layers properly separated?
- [ ] **Dependency direction**: Do dependencies point inward (domain has no external deps)?
- [ ] **Circular dependencies**: Any module import cycles?
- [ ] **Dead code**: Unused exports, unreachable branches, commented-out code?
- [ ] **Configuration**: Are environment-specific values externalized?
- [ ] **Error handling**: Consistent error strategy (no silent catches)?
- [ ] **Logging**: Structured, appropriate levels, no PII?
- [ ] **API consistency**: Uniform response shapes, error formats, naming conventions?

### Step 5: Report

Produce `CODE_QUALITY_REPORT.md` (or add to planning directory if issue context):

```markdown
# Code Quality Report

**Date:** {date}
**Scope:** {full project or specific area}
**Stack:** {detected stack}

## Summary
| Category | Score | Status |
|----------|-------|--------|
| Static Analysis | N errors, N warnings | ✓/⚠/✗ |
| Type Safety | N errors | ✓/⚠/✗ |
| Test Coverage | N% | ✓/⚠/✗ |
| Dependencies | N vulnerabilities | ✓/⚠/✗ |
| Architecture | see findings | ✓/⚠/✗ |

## Critical Issues (fix immediately)
1. ...

## Important Issues (fix soon)
1. ...

## Recommendations (improve over time)
1. ...

## Metrics
(table from Step 3)

## Suggested Tool Configuration
(if linting/formatting is not set up, provide config)
```

### Step 6: Suggest Expert Mode

Based on detected stack, recommend relevant `/language/*-pro` commands:

- TypeScript detected → "Use `/language/typescript-pro` for advanced patterns"
- PHP detected → "Use `/language/php-pro` for modern PHP patterns"
- Python detected → "Use `/language/python-pro` for type-safe Python"
- Terraform files → "Use `/language/terraform-pro` for IaC best practices"
- AWS resources → "Use `/language/aws-pro` for architecture guidance"
- Azure resources → "Use `/language/azure-pro` for architecture guidance"
- GCP resources → "Use `/language/gcp-pro` for architecture guidance"
- React detected → "Use `/language/javascript-react-pro` for React patterns"

### Quality Gates
- All available static analysis tools were run
- Metrics are quantified (not just "looks good")
- Critical issues have specific file:line references
- Recommendations are prioritized (critical → important → nice-to-have)
