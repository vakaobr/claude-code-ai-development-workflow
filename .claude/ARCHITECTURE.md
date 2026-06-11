# Architecture Overview

Lean SDLC system aligned with Claude Code best practices.

## Visual Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      USER INTERFACE                          │
│                    /sdlc command                             │
│              (parse input, invoke agent)                     │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   ORCHESTRATION LAYER                        │
│                  SDLC Orchestrator Agent                     │
│                                                              │
│  • Phase state machine: Research → Plan → Implement → Review│
│  • Gate enforcement                                          │
│  • Review-fix loop (max 3)                                   │
│  • State via STATUS.md                                       │
└─────────────────────────┬───────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│researching-  │ │planning-     │ │implementing- │
│code          │ │solutions     │ │code          │
└──────────────┘ └──────────────┘ └──────────────┘
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
┌──────────────┐         ┌──────────────┐
│reviewing-    │         │review-fix    │
│code          │         │              │
└──────────────┘         └──────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│                  SECURITY LAYER (DevSecOps)                   │
│               Security Analyst Agent (opus)                   │
│                                                              │
│  7a: /security ──▶ 7b: /security/pentest ──▶ 7c: /redteam  │
│  (OWASP, STRIDE)   (Shannon dynamic)         (AI/LLM audit) │
│       │                    │                       │         │
│       └────────────────────┴───────────────────────┘         │
│                            │                                  │
│                            ▼                                  │
│                    /security/harden                            │
│                  (P0 fix → re-verify)                         │
│                                                              │
│  Skill: offensive-security (exploit patterns reference)      │
│  MCP: Shannon (dynamic pentest via OAuth wrapper)            │
│  Tool: OBLITERATUS (AI alignment analysis, GPU required)     │
└─────────────────────────┬───────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│                   VISUALIZATION LAYER                        │
│                Visual Explainer Skill (sonnet)               │
│                                                              │
│  /visual/generate-web-diagram    HTML diagrams (Mermaid)    │
│  /visual/diff-review             Before/after code review   │
│  /visual/plan-review             Plan vs codebase analysis  │
│  /visual/project-recap           Mental model snapshot      │
│  /visual/generate-slides         Slide deck presentations   │
│  /visual/generate-visual-plan    Feature implementation viz │
│  /visual/fact-check              Document accuracy check    │
│  /visual/share                   Deploy to Vercel           │
│                                                              │
│  Output: ~/.agent/diagrams/ (self-contained HTML files)     │
└─────────────────────────┬───────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│                      ARTIFACTS                               │
│                  docs/{issue-name}/                          │
│                                                              │
│  ├── STATUS.md           (progress tracker)                  │
│  ├── RESEARCH.md         (what we found)                     │
│  ├── PLAN.md             (what we'll build)                  │
│  ├── IMPLEMENTATION.md   (what we built)                     │
│  ├── REVIEW.md           (is it ready?)                      │
│  ├── SECURITY_AUDIT.md   (7a: static findings)              │
│  ├── PENTEST_REPORT.md   (7b: confirmed exploits)           │
│  ├── AI_THREAT_MODEL.md  (7c: LLM attack surface)           │
│  └── HARDEN_PLAN.md      (fix plan + regression tests)      │
└─────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

### User Interface Layer

**Command (`/sdlc`):**
- Parse arguments
- Validate input
- Invoke agent
- No workflow logic

### Orchestration Layer

**SDLC Orchestrator Agent:**
- Execute phases sequentially
- Enforce gates between phases
- Manage review-fix loop
- Track state in STATUS.md
- Provide user notifications

### Capabilities Layer

**Skills (folder-based, Anthropic official format):**

Each skill lives in `.claude/skills/{name}/SKILL.md` with YAML frontmatter (`name`, `description`, `model`, `metadata`) and standardized body (Mindset, Goal, Instructions, Output Format, Quality Check, Common Issues).

**Model Routing:** Skills and commands declare their preferred model via the `model:` frontmatter field. Deep reasoning phases (research, plan, implement) use `opus`; checklist/template phases (discover, review, security, deploy, observe, retro) use `sonnet`.

| Skill | Mindset | Output |
|-------|---------|--------|
| researching-code | Understand minimum context | RESEARCH.md |
| planning-solutions | Define WHAT, not HOW | PLAN.md |
| implementing-code | Build working software | IMPLEMENTATION.md + code |
| reviewing-code | Is this deployable? | REVIEW.md |
| review-fix | Fix blocking issues only | Fixed code |
| offensive-security | Think like an attacker | Exploit patterns, OWASP/STRIDE reference |
| visual-explainer | Generate rich HTML visualizations | Self-contained HTML pages in ~/.agent/diagrams/ |

### Visualization Layer

**Visual Explainer Skill (`visual-explainer/SKILL.md`):**
- Generates self-contained HTML pages with Mermaid diagrams, CSS Grid layouts, Chart.js dashboards
- Commands namespaced under `/visual/` (8 commands)
- Anti-slop guardrails: forbidden fonts, colors, and patterns to ensure distinctive output
- Supports light/dark themes, responsive navigation, zoom/pan on diagrams
- Optional AI image generation via `surf-cli`
- Output: `~/.agent/diagrams/` (persistent across sessions)

| Command | Purpose | Model |
|---------|---------|-------|
| generate-web-diagram | Any HTML diagram | sonnet |
| diff-review | Before/after architecture + code review | opus |
| plan-review | Plan vs codebase risk assessment | opus |
| project-recap | Mental model snapshot | opus |
| fact-check | Verify document accuracy | opus |
| generate-slides | Magazine-quality slide deck | sonnet |
| generate-visual-plan | Visual implementation plan | opus |
| share | Deploy to Vercel | — |

### Retrieval Layer (Optional)

**claude-context MCP (`@zilliz/claude-context-mcp`):**
- Adopted package — not custom-built (see ADR-001)
- Provides hybrid BM25 + dense vector search over AST-indexed code
- Tree-sitter parses code into semantic chunks (functions, classes, methods)
- Merkle tree tracks file hashes for incremental re-indexing
- Embedding via Ollama (`nomic-embed-text`) or cloud providers (OpenAI, Voyage, Gemini)
- Storage via Docker Milvus (local) or Zilliz Cloud (managed)

| Tool | Purpose |
|------|---------|
| `search_code` | Hybrid semantic + keyword search over code chunks |
| `index_codebase` | Build or incrementally update the code index |
| `get_indexing_status` | Check index health, progress, file/chunk counts |
| `clear_index` | Remove index for a codebase |

**Integration points:**
- `researching-code` skill: Step 0c queries retrieval scoped to candidate files from repo map + symbol index; results feed into Step 0d reranking and Step 0e context pack assembly
- `implementing-code` skill: Optional pattern discovery via `search_code` + optional impact analysis via dependency graph
- `/retrieval` command: Manual search, index management, status checks
- `/retrieval/setup` command: Interactive setup wizard (Ollama + Milvus, Zilliz Cloud, etc.)

**Graceful degradation:** All skills work identically without retrieval. If `claude-context` is not configured or services are down, skills fall back to Glob/Grep/Read.

### Context Engine (Code Intelligence Layer)

Multi-level context pipeline that reduces token usage and improves search accuracy through structural analysis, dependency tracing, and relevance ranking:

```
Level 1: Repo Map + Symbol Index (≤3K tokens)
  Generated by: /discover (Step 3) or /repo-map (standalone)
  Stored in:    01_DISCOVERY.md ## Repository Map + ## Symbol Index
  Contains:     file tree + symbols (map), type:name:file:line entries (index)
  Always works: uses Glob + Grep (no MCP required)
       │
       ▼ identifies candidate files + relevant symbols
Level 1b: Dependency Graph (in-context, repos ≥50 files)
  Built by:     researching-code Step 0b
  Source:        Grep for import/export statements per language
  Contains:     file → [imports, imported-by, tested-by] adjacency list
  Stored:       in LLM context only (ephemeral, not persisted)
       │
       ▼ enriches candidates with relationship data
Level 2: Targeted Detail (per-file context)
  Source:       search_code MCP (if available) or Grep/Read (fallback)
  Scoped to:    candidate files from Level 1
  Contains:     full code chunks, implementations
       │
       ▼ raw results
Level 2b: Reranking (repos ≥50 files, >5 candidates)
  Built by:     researching-code Step 0d
  Scoring:      keyword overlap (40%) + dependency proximity (35%) + file-type (25%)
  Output:       top-8 candidates re-ordered by composite relevance score
       │
       ▼ ranked results
Level 3: Context Pack (≤8 files)
  Built by:     researching-code Step 0e
  Contains:     seed files + 1-hop dependency imports + test files
  Budget:       hard cap 8 files; progressive read depth (full/partial/sections)
```

**Data flow:** `/discover` → `01_DISCOVERY.md` (repo map + symbol index) → `researching-code` Step 0a reads map+index → Step 0b builds dependency graph → Step 0c targeted search → Step 0d reranks → Step 0e assembles context pack → Steps 1-2 analyze pack files

**Scaling behavior:**

| Repo Size | Pipeline |
|-----------|----------|
| < 50 files | Level 1 → Level 2 → context pack (skip graph + reranking) |
| 50–200 files | Full pipeline: all levels |
| 200–500 files | Truncated index; primary dirs only for graph |
| > 500 files | Directory-level map; relies on MCP search_code for Level 2 precision |

**Session persistence:**
- Cross-session: `01_DISCOVERY.md` (repo map + symbol index)
- Intra-session: Claude Code context window (dependency graph + context pack)

**Commands:**
- `/repo-map` — standalone map + symbol index generation
- `/discover` — auto-generates map + index as Step 3

**Inspired by:** Aider's repo map (Tree-sitter + PageRank), Sourcegraph heuristic scoring, and RAG reranking patterns. Our approach uses Glob + Grep (no runtime dependencies) with LLM-native reasoning for reranking.

### Security Layer

**Security Analyst Agent (`security-analyst.md`):**
- Activates during `/security`, `/security/pentest`, `/security/redteam-ai`, `/security/harden`
- "No exploit, no report" — every Critical/High finding requires a working PoC
- Combines static analysis (OWASP, STRIDE) with dynamic testing (Shannon) and AI auditing (OBLITERATUS)
- Produces findings with CVSS scores, reproduction steps, and fix recommendations

**Shannon MCP Integration:**
- Autonomous pentester running in Docker
- Connected via OAuth wrapper (`.claude/scripts/shannon-mcp-wrapper.sh`)
- Reads token dynamically from `~/.claude/credentials.json` — no manual key management
- Cost: ~$50/run under pay-per-token; monitor usage under Team subscription

**OBLITERATUS (optional, GPU required):**
- Mechanistic interpretability toolkit for open-source LLMs
- Reveals alignment constraint structure, jailbreak surface, self-repair robustness
- Only relevant when the application embeds a self-hosted open-source model

### Memory Layer

**Two-tier knowledge persistence:**

| Tier | Location | Scope | Loaded |
|------|----------|-------|--------|
| Tier 1: Repo-shared | `CLAUDE.md ## Learnings` | Team-visible, versioned in git | Always (part of CLAUDE.md) |
| Tier 2: Project-personal | `~/.claude/projects/{hash}/memory/` | Per-user, auto-loaded | MEMORY.md always; topic files on demand |

**Auto-memory files:** MEMORY.md (index, max 200 lines), patterns.md, decisions.md, learnings.md

**Data flow:** `/retro` writes to both tiers. New sessions get CLAUDE.md + MEMORY.md automatically.

### Data Layer

**5 core artifacts per issue + up to 4 security artifacts:**

| File | Purpose | Size |
|------|---------|------|
| STATUS.md | Progress tracking | ~30 lines |
| RESEARCH.md | Research findings | ~50 lines |
| PLAN.md | Implementation plan | ~80 lines |
| IMPLEMENTATION.md | What was built | ~60 lines |
| REVIEW.md | Review findings | ~40 lines |
| SECURITY_AUDIT.md | 7a: Static findings (OWASP, STRIDE, CVEs) | ~60 lines |
| PENTEST_REPORT.md | 7b: Shannon-confirmed exploits with PoCs | ~80 lines |
| AI_THREAT_MODEL.md | 7c: LLM attack surface, prompt injection risks | ~60 lines |
| HARDEN_PLAN.md | Prioritized fix list, patches, regression tests | ~80 lines |

---

## Design Principles

### 1. Trust Claude Code

Claude Code handles:
- Context management (200K window)
- File reading on demand
- Session resumption

We don't need:
- Summary artifacts (removed)
- Pseudo-code state machines (removed)
- LLM parameter specs (removed)

### 2. Minimal Artifacts

**Before:** 8+ files per issue
**After:** 5 files per issue

Consolidated:
- CODE_RESEARCH.md + RESEARCH_SUMMARY.md → RESEARCH.md
- IMPLEMENTATION_PLAN.md + PROJECT_SPEC.md + PLAN_SUMMARY.md → PLAN.md
- IMPLEMENTATION_SUMMARY.md → IMPLEMENTATION.md
- CODE_REVIEW.md → REVIEW.md

### 3. Extended Thinking

Skills use extended thinking for complex reasoning:
- Research: "Think deeply about hidden dependencies"
- Planning: "Think harder about edge cases"
- Review: "Think a lot about security"

### 4. Lean Communication

Essential notifications only:
- Phase start
- Phase complete
- Errors/blockers
- Final completion

---

## Workflow State Machine

```
[START]
   │
   ▼
Research ──gate──▶ Plan ──gate──▶ Implement ──gate──▶ Review
                                                       │
                                           ┌───────────┴───────────┐
                                           │                       │
                                       APPROVED               NEEDS_FIX
                                           │                       │
                                           ▼                       ▼
                                      Security (7a)            Fix (max 3)
                                           │                       │
                                           ▼                       ▼
                                      Pentest (7b)             Review
                                      (optional)
                                           │
                                           ▼
                                      AI Audit (7c)
                                      (if LLMs)
                                           │
                                           ▼
                                       Harden (8)
                                      (if findings)
                                           │
                                           ▼
                                      [DEPLOY →
                                       OBSERVE →
                                       RETRO]
```

### Gate Checks

| Gate | Check |
|------|-------|
| Research → Plan | 3 questions answered |
| Plan → Implement | Scope + phases + criteria defined |
| Implement → Review | All phases done + tests pass |
| Review → Security | APPROVED verdict |
| Security → Pentest | SECURITY_AUDIT.md produced |
| Pentest → Harden | PENTEST_REPORT.md produced (or skipped) |
| Harden → Deploy | P0 fixes implemented + tests pass |

---

## Comparison: Before vs After

| Aspect | Before | After |
|--------|--------|-------|
| Artifacts | 8+ | 5 |
| Orchestrator | 860 lines | 250 lines |
| Skills | 400+ lines each | 100-200 lines each |
| LLM params | Specified | Trust Claude Code |
| Resume logic | Complex `--from-*` | Simple `--resume` |
| Communication | Extensive templates | Essential only |

---

## Quality Invariants

1. **No logic in command** - Only parsing and invocation
2. **Stateless skills** - Procedures, not state holders
3. **Agent orchestrates** - Only agent manages workflow
4. **Minimal artifacts** - 5 files, no duplication
5. **Trust the tool** - Claude Code handles context
6. **Extended thinking** - For complex reasoning
7. **Max 3 fix iterations** - Escalate if stuck

---

## Delivery Layers

A conceptual **lens** over the 11 phases — four layers describing *why* each capability exists. It is a way to read the framework, not a fifth process.

| Layer | Purpose | Phases / Capabilities |
|-------|---------|-----------------------|
| **① Spec** | Decide *what* to build and to *what bar* | `/roadmap` (project phases) → `/discover` → `/research` → `/design-system` (ADRs) → `/plan`; the **Quality Contract** (CLAUDE.md); `03_PROJECT_SPEC.md` |
| **② Verifier** | Prove it works and is safe | `/review` · `/security` (+`/security/harden`) · `/devops/ci-pipeline` · `/deploy-plan` · the `verify` skill · `qa-reviewer` / `sre-reviewer` / `security-*` agents |
| **③ Loop** | Execute autonomously, bounded | `sdlc-orchestrator` (one issue, end-to-end) · `/roadmap-run` (one roadmap phase, one bounded slice per call, driven by native `/loop`) |
| **④ Environment** | Give the agent context & tools | `CLAUDE.md` · skills · `claude-context` semantic retrieval · memory · MCP integrations (markitdown, firecrawl, …) |

### Phase → Layer map (all 11 phases)
| Phase | Layer |
|-------|-------|
| 1 Discovery | Spec |
| 2 Research | Spec |
| 3 Design | Spec |
| 4 Planning | Spec |
| 5 Implementation | Loop (executes the plan; can be driven by orchestrator/`/roadmap-run`) |
| 6 Review | Verifier |
| 7 Security (7a/7b/7c) | Verifier |
| 8 Harden | Verifier |
| 9 Deploy | Verifier |
| 10 Observe | Verifier |
| 11 Retro | Environment (feeds learnings back into CLAUDE.md / memory) |
| (cross-cutting) Quality Contract | Spec (set) → Verifier (enforced) |

### Quality Contract — rationale & tooling
The Contract (canonical in `CLAUDE.md`) sets a higher, explicit bar:
- **Cognitive** (not cyclomatic) complexity — measures human comprehension difficulty, the better maintainability signal. Tiers: frontend ≤ 12 · backend ≤ 15 · compilers/engines ≤ 25. Tooling: eslint `complexity`, ruff `C901`/mccabe, PHPMD/PHPStan, Go `gocyclo`, SonarQube cognitive-complexity.
- **Coverage ≥ 90%** (critical paths ≥ 95%).
- **BDD** Given/When/Then acceptance criteria (Spec → executable specs in Verifier).
- **Architecture**: MVVM (frontend) / Hexagonal — ports & adapters (backend).
These target the **projects the framework builds**, enforced by their CI; this prompt-only repo has no runtime code of its own.
