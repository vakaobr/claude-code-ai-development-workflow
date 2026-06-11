## Quality: Lint & Formatting Setup

Configure linting, formatting, and pre-commit hooks for the project. Context: `$ARGUMENTS`

### Instructions

Auto-detect the project stack and set up a comprehensive linting, formatting, and automated quality enforcement pipeline.

### Step 1: Stack Detection

Identify the primary language(s) and existing tooling:

| File | Language | Linter | Formatter |
|------|----------|--------|-----------|
| `package.json` | JS/TS | ESLint | Prettier |
| `tsconfig.json` | TypeScript | ESLint + TypeScript plugin | Prettier |
| `composer.json` | PHP | PHPStan + PHPCS | PHP-CS-Fixer |
| `pyproject.toml` | Python | Ruff | Ruff format |
| `*.tf` | Terraform | tflint | terraform fmt |
| `Cargo.toml` | Rust | clippy | rustfmt |
| `go.mod` | Go | golangci-lint | gofmt |

Check what's already configured vs missing.

### Step 1b: Enforce the Quality Contract complexity limits

Configure each linter to fail builds that exceed the **Quality Contract** cognitive-complexity limits (`CLAUDE.md`: frontend ≤ 12 · backend ≤ 15 · compilers/engines ≤ 25). Map per language:

| Language | Rule / tool | Example |
|----------|-------------|---------|
| JS/TS | ESLint `complexity` | `"complexity": ["error", 12]` (frontend) / `15` (backend) |
| Python | Ruff `C901` (mccabe) | `[tool.ruff.lint.mccabe] max-complexity = 15` |
| PHP | PHPMD `CyclomaticComplexity` / PHPStan | rule threshold 15 |
| Go | `gocyclo` / golangci-lint | `gocyclo: min-complexity: 15` |
| Any | SonarQube cognitive-complexity | quality gate ≤ tier |

Pick the tier from the codebase role (UI vs service vs engine). Wire it into the pre-commit hook + CI so violations block merge.

### Step 2: Generate Configurations

For each detected language, generate the appropriate config if not present:

**JavaScript/TypeScript (ESLint + Prettier):**
```javascript
// eslint.config.js (flat config, ESLint 9+)
import js from '@eslint/js';
import tsPlugin from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';
import reactHooks from 'eslint-plugin-react-hooks';
import jsxA11y from 'eslint-plugin-jsx-a11y';

export default [
  js.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        project: './tsconfig.json',
      },
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
      'react-hooks': reactHooks,
      'jsx-a11y': jsxA11y,
    },
    rules: {
      // TypeScript strict rules
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/strict-boolean-expressions': 'warn',
      '@typescript-eslint/no-floating-promises': 'error',

      // React
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',

      // General
      'no-console': ['warn', { allow: ['warn', 'error'] }],
      'prefer-const': 'error',
      'no-var': 'error',
    },
  },
  {
    ignores: ['dist/', 'node_modules/', 'coverage/', '*.config.*'],
  },
];
```

```json
// .prettierrc
{
  "semi": true,
  "singleQuote": true,
  "trailingComma": "all",
  "printWidth": 100,
  "tabWidth": 2,
  "arrowParens": "always",
  "endOfLine": "lf"
}
```

**Python (Ruff — replaces black, isort, flake8, pyflakes, etc.):**
```toml
# pyproject.toml
[tool.ruff]
target-version = "py311"
line-length = 100
src = ["src", "tests"]

[tool.ruff.lint]
select = [
  "E",   # pycodestyle errors
  "W",   # pycodestyle warnings
  "F",   # pyflakes
  "I",   # isort
  "N",   # pep8-naming
  "UP",  # pyupgrade
  "B",   # bugbear
  "A",   # builtins shadowing
  "S",   # bandit (security)
  "T20", # print statements
  "SIM", # simplify
  "TCH", # type-checking imports
  "RUF", # ruff-specific
  "PTH", # pathlib
  "ERA", # commented-out code
]
ignore = ["S101"]  # Allow assert in tests

[tool.ruff.lint.per-file-ignores]
"tests/**" = ["S101", "T20"]

[tool.ruff.format]
quote-style = "double"
docstring-code-format = true

[tool.mypy]
python_version = "3.11"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
```

**PHP (PHPStan + PHP-CS-Fixer):**
```neon
# phpstan.neon
parameters:
    level: 8
    paths:
        - src
    excludePaths:
        - vendor
        - tests
    reportUnmatchedIgnoredErrors: false
```

```php
// .php-cs-fixer.php
<?php
$finder = PhpCsFixer\Finder::create()
    ->in(__DIR__ . '/src')
    ->in(__DIR__ . '/tests');

return (new PhpCsFixer\Config())
    ->setRules([
        '@PSR12' => true,
        '@PHP82Migration' => true,
        'strict_types' => true,
        'declare_strict_types' => true,
        'array_syntax' => ['syntax' => 'short'],
        'no_unused_imports' => true,
        'ordered_imports' => ['sort_algorithm' => 'alpha'],
        'trailing_comma_in_multiline' => true,
    ])
    ->setFinder($finder)
    ->setRiskyAllowed(true);
```

**Terraform (tflint):**
```hcl
# .tflint.hcl
config {
  module = true
}

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

plugin "aws" {          # or "azurerm" / "google"
  enabled = true
  version = "0.30.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

rule "terraform_naming_convention" {
  enabled = true
}

rule "terraform_documented_variables" {
  enabled = true
}

rule "terraform_documented_outputs" {
  enabled = true
}
```

### Step 3: Git Hooks (Pre-commit)

Set up automated quality checks before every commit:

**Option A: lint-staged + husky (JS/TS projects):**
```json
// package.json
{
  "lint-staged": {
    "*.{ts,tsx}": ["eslint --fix --max-warnings 0", "prettier --write"],
    "*.{js,jsx}": ["eslint --fix --max-warnings 0", "prettier --write"],
    "*.{json,md,yml,yaml}": ["prettier --write"],
    "*.py": ["ruff check --fix", "ruff format"],
    "*.php": ["php-cs-fixer fix"],
    "*.tf": ["terraform fmt"]
  }
}
```

```bash
# Setup commands
npx husky init
echo "npx lint-staged" > .husky/pre-commit
```

**Option B: pre-commit framework (multi-language):**
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-json
      - id: check-added-large-files
        args: ['--maxkb=500']
      - id: detect-private-key
      - id: no-commit-to-branch
        args: ['--branch', 'main']

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.3.0
    hooks:
      - id: ruff
        args: ['--fix']
      - id: ruff-format

  - repo: https://github.com/pre-commit/mirrors-eslint
    rev: v9.0.0
    hooks:
      - id: eslint
        args: ['--fix', '--max-warnings=0']
        additional_dependencies:
          - eslint
          - typescript
          - '@typescript-eslint/parser'
          - '@typescript-eslint/eslint-plugin'

  - repo: https://github.com/antonbabenko/pre-commit-terraform
    rev: v1.88.0
    hooks:
      - id: terraform_fmt
      - id: terraform_validate
      - id: terraform_tflint
```

### Step 4: Editor Configuration

```ini
# .editorconfig
root = true

[*]
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
charset = utf-8

[*.{js,ts,tsx,jsx,json,yml,yaml,css,scss,html}]
indent_style = space
indent_size = 2

[*.{py,php}]
indent_style = space
indent_size = 4

[*.{tf,tfvars}]
indent_style = space
indent_size = 2

[Makefile]
indent_style = tab
```

### Step 5: NPM/Composer/Pip Scripts

Add quality commands to the package manager:

```json
// package.json scripts
{
  "lint": "eslint . --max-warnings 0",
  "lint:fix": "eslint . --fix",
  "format": "prettier --write .",
  "format:check": "prettier --check .",
  "typecheck": "tsc --noEmit",
  "quality": "npm run lint && npm run typecheck && npm run format:check"
}
```

```toml
# pyproject.toml scripts (via taskipy or just document)
# ruff check . && ruff format --check . && mypy . --strict
```

### Output
- Configuration files for detected stack
- Pre-commit hooks setup
- Editor configuration
- NPM/pip/composer scripts for CI integration
- Summary of what was configured and why

### Quality Gates
- Lint config targets zero-warning mode (not just zero-error)
- Formatter is opinionated (no manual style debates)
- Pre-commit hooks actually run on commit
- Editor config aligns with lint/format rules
- CI can run the same quality checks as local hooks
