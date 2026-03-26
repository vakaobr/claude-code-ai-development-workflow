# AI-Powered Software Development Lifecycle (SDLC) — DevSecOps Edition

> A comprehensive DevSecOps slash-command workflow for Claude Code that covers the **entire** software development lifecycle — from discovery through security hardening, deployment, and post-deployment observability. Includes an integrated red team layer and a rich visualization engine for turning artifacts into interactive HTML pages.

### Integrated External Tools

This project synthesizes and extends several open-source tools, each bringing distinct capabilities:

| Tool | What It Brings | Commands |
|------|---------------|----------|
| [**claude-code-ai-development-workflow**](https://github.com/DenizOkcu/claude-code-ai-development-workflow) by DenizOkcu | The original 4-phase slash command workflow (Research → Plan → Execute → Review) that forms the backbone of the SDLC pipeline | `/research`, `/plan`, `/implement`, `/review` |
| [**llm-knowledge-hub**](https://github.com/OmarKAly22/llm-knowledge-hub) by OmarKAly22 | LLM best practices, prompt engineering, agentic AI patterns, RAG, security, and evaluation guides | `/ai-integrate`, language expert commands |
| [**Shannon**](https://github.com/KeygraphHQ/shannon) by KeygraphHQ | Autonomous AI pentester — proves exploits with working PoCs, not just flags theoretical risks. Runs as an MCP server in Docker | `/security/pentest` |
| [**OBLITERATUS**](https://github.com/elder-plinius/OBLITERATUS) by elder-plinius | Mechanistic interpretability toolkit for AI model alignment analysis — reveals jailbreak surfaces and self-repair robustness in self-hosted LLMs | `/security/redteam-ai` |
| [**visual-explainer**](https://github.com/nicobailon/visual-explainer) by nicobailon | Generates self-contained HTML pages with Mermaid diagrams, interactive zoom/pan, dark/light themes, KPI dashboards, slide decks, and anti-AI-slop guardrails. Turns markdown artifacts into browser-quality visualizations | `/visual/*` (8 commands) |
| [**n8n-MCP**](https://github.com/czlonkowski/n8n-mcp) by czlonkowski | MCP server bridging n8n workflow automation with Claude Code — access 1,084+ nodes, 2,709 templates, and optionally manage a live n8n instance (CRUD workflows, trigger executions). Self-hosted or hosted | `/n8n`, `/n8n/setup` |
| [**Firecrawl**](https://github.com/firecrawl/firecrawl) by firecrawl | Web scraping, crawling, and structured data extraction via MCP. Fallback when built-in `WebFetch` fails on JS-rendered or anti-bot protected pages. Self-hosted (Docker) or cloud API | `/firecrawl`, `/firecrawl/setup` |
| [**claude-context**](https://github.com/zilliztech/claude-context) by Zilliz | Semantic code retrieval via MCP — hybrid BM25 + vector search over AST-indexed codebases. Tree-sitter parsing, Merkle tree incremental indexing, multiple embedding providers (Ollama, OpenAI, Voyage, Gemini). Enhances `/research` and `/implement` with semantic search | `/retrieval`, `/retrieval/setup` |

Extended with: Discovery, Architecture/ADR, DevSecOps security layer, Deployment, Observability, Retrospective phases, performance testing, hotfix workflow, multi-agent orchestration, and self-improving CLAUDE.md via automated retrospectives.

**[View the interactive slide deck overview](https://ai-sdlc.andersonleite.me/sdlc-overview-deck.html)** — an 18-slide visual summary of the entire workflow, built with the integrated visual-explainer. ([local](docs/sdlc-overview-deck.html))

---

## Why This Exists

Most AI-assisted coding workflows stop at "write code → review code." Real software delivery has **10+ distinct activities** that benefit from structured AI assistance. This project fills the gaps:

| Gap in Existing Workflows | How This Project Addresses It |
|---|---|
| No threat modeling or security audit phase | `/security` (static OWASP/STRIDE) + `/security/pentest` (dynamic via Shannon) |
| No dynamic penetration testing | Shannon MCP integration — proves exploits, not just flags risks |
| No AI/LLM-specific security testing | `/security/redteam-ai` for prompt injection, alignment analysis (OBLITERATUS) |
| No security fix loop | `/security/harden` prioritizes (P0–P3), patches, and re-verifies |
| No architecture decision records | `/design-system` produces ADRs + system diagrams |
| No performance/load testing phase | `/perf-test` generates benchmarks, profiles, and load scripts |
| No deployment automation guidance | `/deploy-plan` creates rollout strategy + rollback playbook |
| No post-deploy observability | `/observe` sets up logging, metrics, alerts, and dashboards |
| No knowledge capture / retrospective | `/retro` generates lessons-learned docs and updates CLAUDE.md + `.claude/LEARNINGS.md` |
| CLAUDE.md bloat wastes tokens every conversation | Tiered architecture: lean always-on CLAUDE.md (~90 lines) + on-demand reference files (learnings, quick reference) — saves ~17K tokens/conversation |
| No multi-feature orchestration | Parallel issue tracking via `00_STATUS.md` per feature |
| No LLM/AI-specific development patterns | `/ai-integrate` for prompt engineering, RAG, eval, and guardrails |
| No visual output for artifacts | `/visual/*` generates HTML pages with Mermaid diagrams, KPI dashboards, slide decks |
| No semantic code understanding | `/retrieval` adds hybrid BM25 + vector search — finds conceptually related code, saves ~40% context tokens |
| LLM searches blindly with no repo structure | Code Intelligence Layer — `/discover` auto-generates repo map + symbol index; `/research` builds dependency graphs, reranks by relevance, and assembles an 8-file context pack |

---

## Quick Start

```bash
# Copy this entire .claude/ directory into your project root.
cp -r .claude/ /path/to/your/project/.claude/

# Start with discovery on a new feature:
/discover Add real-time collaborative editing to the document editor

# This generates an issue name (e.g., "add-realtime-collab") and kicks off the 10-phase workflow.

# Resume an incomplete workflow (auto-detects from .claude/planning/):
/sdlc/continue
```

---

## The DevSecOps Workflow

```
┌─────────────┐    ┌──────────────┐    ┌────────────────┐    ┌──────────────┐
│ 1. DISCOVER  │───▶│ 2. RESEARCH  │───▶│ 3. DESIGN      │───▶│ 4. PLAN      │
│ /discover    │    │ /research    │    │ /design-system │    │ /plan        │
└─────────────┘    └──────────────┘    └────────────────┘    └──────────────┘
                                                                     │
       ┌─────────────────────────────────────────────────────────────┘
       ▼
┌──────────────┐    ┌────────────────┐
│ 5. IMPLEMENT │───▶│ 6. REVIEW      │
│ /implement   │    │ /review        │
└──────────────┘    └────────┬───────┘
                             │
       ┌─────────────────────┘
       ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    SECURITY LAYER (DevSecOps)                             │
│                                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐               │
│  │ 7a. STATIC   │───▶│ 7b. PENTEST  │───▶│ 7c. AI AUDIT │               │
│  │ /security    │    │ /security/   │    │ /security/   │               │
│  │ (OWASP,STRIDE)    │ pentest      │    │ redteam-ai   │               │
│  └──────────────┘    │ (Shannon)    │    │ (OBLITERATUS) │              │
│                      └──────────────┘    └──────────────┘               │
│                             │                                            │
│                      ┌──────┴───────┐                                    │
│                      │ 8. HARDEN    │                                    │
│                      │ /security/   │                                    │
│                      │ harden       │                                    │
│                      └──────────────┘                                    │
└──────────────────────────────────────────────────┬───────────────────────┘
                                                   │
       ┌───────────────────────────────────────────┘
       ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ 9. DEPLOY    │───▶│ 10. OBSERVE  │───▶│ 11. RETRO    │
│ /deploy-plan │    │ /observe     │    │ /retro       │
└──────────────┘    └──────────────┘    └──────────────┘
```

### Phase Summaries

| # | Phase | Command | Artifacts Produced |
|---|-------|---------|-------------------|
| 1 | **Discover** | `/discover [description]` | Issue name, `01_DISCOVERY.md` (with repo map + symbol index), `00_STATUS.md` |
| 2 | **Research** | `/research {issue}` | `02_CODE_RESEARCH.md`, updated `00_STATUS.md` |
| 3 | **Design** | `/design-system {issue}` | `03_ARCHITECTURE.md`, `03_ADR-*.md`, `03_PROJECT_SPEC.md` |
| 4 | **Plan** | `/plan {issue}` | `04_IMPLEMENTATION_PLAN.md`, test strategy |
| 5 | **Implement** | `/implement {issue}` | Source code, tests, updated `00_STATUS.md` |
| 6 | **Review** | `/review {issue}` | `06_CODE_REVIEW.md`, approval/rejection status |
| 7a | **Static Security** | `/security {issue}` | `07a_SECURITY_AUDIT.md` (OWASP, STRIDE, deps) |
| 7b | **Dynamic Pentest** | `/security/pentest {issue}` | `07b_PENTEST_REPORT.md` (Shannon-confirmed exploits) |
| 7c | **AI Model Audit** | `/security/redteam-ai {issue}` | `07c_AI_THREAT_MODEL.md` (only if LLMs in stack) |
| 8 | **Harden** | `/security/harden {issue}` | `08_HARDEN_PLAN.md`, P0 patches, GitHub issues |
| 9 | **Deploy** | `/deploy-plan {issue}` | `09_DEPLOY_PLAN.md`, rollback playbook |
| 10 | **Observe** | `/observe {issue}` | `10_OBSERVABILITY.md`, alert definitions |
| 11 | **Retro** | `/retro {issue}` | `11_RETROSPECTIVE.md`, `.claude/LEARNINGS.md`, CLAUDE.md updates |

---

## Security Commands (DevSecOps)

| Command | Phase | What It Does |
|---------|-------|--------------|
| `/security/pentest {issue}` | 7b | Dynamic pentest via Shannon — only reports proven exploits with PoCs |
| `/security/redteam-ai {issue}` | 7c | AI/LLM threat modeling — prompt injection surface, OBLITERATUS analysis |
| `/security/harden {issue}` | 8 | Prioritized fix plan (P0–P3), implements P0 patches, creates GitHub issues |

### The Security Analyst Agent

A dedicated `security-analyst` agent activates during all security phases. It enforces the **"No Exploit, No Report"** standard — theoretical risks without working PoCs are classified as Informational, never Critical/High. Every finding includes CVSS score, CWE, reproduction steps, and fix recommendation.

### Shannon Integration (Autonomous AI Pentester)

Shannon runs as an MCP server connected via an OAuth wrapper that reads your Claude Code token dynamically — no API key management needed.

**Setup:**
```bash
# 1. Clone Shannon next to your project
git clone https://github.com/KeygraphHQ/shannon.git ./shannon

# 2. Ensure Docker is running (Shannon runs in containers)
docker --version

# 3. Authenticate with Claude Code (only needed once)
claude login

# That's it. The MCP wrapper handles everything else automatically.
```

**How it works:**
- `.claude/scripts/shannon-mcp-wrapper.sh` reads `~/.claude/credentials.json` at startup
- Extracts OAuth token, builds Shannon's MCP server if needed, launches it
- When token rotates, just `claude login` — next call picks it up automatically

> Never run Shannon against production. It actively exploits — creates users, modifies data. Staging or localhost only.

### OBLITERATUS (AI Model Auditing)

Relevant **only** when your app embeds a self-hosted open-source LLM (Llama, Mistral, etc.). For cloud APIs (Claude, GPT), skip this and use the prompt injection patterns from `/security/redteam-ai` instead.

OBLITERATUS requires a GPU. See the [OBLITERATUS repo](https://github.com/elder-plinius/OBLITERATUS) for installation.

## Bonus Commands

| Command | Purpose |
|---------|---------|
| `/ai-integrate {issue}` | Add LLM/AI capabilities — prompt design, RAG, eval, guardrails |
| `/perf-test {issue}` | Performance testing — benchmarks, profiling, load tests |
| `/hotfix [description]` | Compressed emergency workflow (research → fix → review → deploy) |

## n8n Workflow Automation

Integrate with [n8n](https://n8n.io/) via the [n8n-MCP](https://github.com/czlonkowski/n8n-mcp) server. Supports self-hosted (npx, Docker) or hosted service, with basic (docs-only) or full (instance management) capabilities.

| Command | Purpose |
|---------|---------|
| `/n8n/setup` | Interactive setup wizard — choose hosting, capabilities, configure credentials |
| `/n8n [request]` | Work with n8n — search nodes, browse templates, build & manage workflows |

**Setup options:**

| Option | Requirements | Best For |
|--------|-------------|----------|
| **Hosted service** | None (sign up at dashboard.n8n-mcp.com) | Quick start, no infra |
| **npx** (recommended) | Node.js 18+ | Most users, fastest local setup |
| **Docker** | Docker installed | Isolated environments |
| **Local dev** | Clone + build from source | Contributors, custom mods |

**Capabilities:**

| Mode | Tools | Requires |
|------|-------|----------|
| **Basic** | Search 1,084+ nodes, browse 2,709 templates, validate workflows | Nothing (docs only) |
| **Full** | Basic + create/edit/delete/trigger workflows on your n8n instance | n8n API URL + API key |

```bash
# First time: run the setup wizard
/n8n/setup

# Then use n8n commands:
/n8n search for Slack nodes
/n8n find templates for email automation
/n8n create a workflow that posts GitHub issues to Slack   # (full mode)
/n8n show all my active workflows                          # (full mode)
```

## Firecrawl Web Scraping

Integrate with [Firecrawl](https://github.com/firecrawl/firecrawl) for powerful web scraping and crawling — especially useful as a fallback when Claude Code's built-in `WebFetch` fails on JavaScript-rendered pages, anti-bot protected sites, or when you need structured data extraction.

| Command | Purpose |
|---------|---------|
| `/firecrawl/setup` | Interactive setup wizard — choose self-hosted (Docker) or cloud API |
| `/firecrawl [request]` | Scrape, crawl, search, map, or extract web content |

**Setup options:**

| Option | Requirements | Best For |
|--------|-------------|----------|
| **Self-hosted Docker** (recommended) | Docker installed | Full control, no API limits |
| **Self-hosted via npx** | Node.js 18+ + self-hosted instance | Lightweight MCP client |
| **Cloud API** | API key from firecrawl.dev | Quick start, no infra |

**Available tools (after setup):**

| Tool | Purpose |
|------|---------|
| `firecrawl_scrape` | Scrape a single URL to clean markdown |
| `firecrawl_crawl` | Recursively crawl a website |
| `firecrawl_search` | Web search + content extraction |
| `firecrawl_map` | Discover all URLs on a site |
| `firecrawl_extract` | LLM-powered structured data extraction |

```bash
# First time: run the setup wizard
/firecrawl/setup

# Then use firecrawl:
/firecrawl scrape https://docs.example.com/api
/firecrawl crawl https://docs.example.com --depth 2
/firecrawl search "React 19 migration guide"
/firecrawl extract product prices from https://store.example.com
```

## Semantic Code Retrieval

Enhance the `/research` and `/implement` phases with semantic code search powered by [claude-context](https://github.com/zilliztech/claude-context) MCP. This adds hybrid BM25 + vector search over AST-indexed codebases — the agent finds relevant code semantically, not just by keyword.

**Why it matters:**

| Benefit | Without Retrieval | With Retrieval |
|---------|-------------------|----------------|
| **Context discovery** | Agent must know what to search for (keyword-dependent) | Agent finds conceptually related code it didn't know to look for |
| **Token efficiency** | Multiple Glob/Grep rounds consume context window (~15-20 files read) | Ranked chunks surface the right code first (~40% token savings) |
| **Research speed** | O(n) iterative search — more rounds for larger codebases | O(1) indexed query — instant results regardless of codebase size |
| **Cross-file awareness** | No understanding of semantic relationships between files | Finds related code even when naming conventions differ |

| Command | Purpose |
|---------|---------|
| `/retrieval/setup` | Interactive setup wizard — choose local (Ollama + Docker Milvus) or cloud (Zilliz Cloud) |
| `/retrieval [request]` | Search, index, check status, or clear the code search index |

**How it works:**
- **Indexing**: Tree-sitter parses your code into semantic chunks (functions, classes, methods), generates embeddings via Ollama, stores in Milvus
- **Search**: Hybrid BM25 (keyword) + dense vector (semantic) search returns ranked code chunks
- **Incremental**: Merkle tree tracks file changes — only modified files are re-indexed
- **Graceful**: All workflow commands work without retrieval. When configured, `/research` and `/implement` automatically query the index before manual Glob/Grep

**Setup options:**

| Option | Requirements | Best For |
|--------|-------------|----------|
| **Fully local** (recommended) | Ollama + Docker | Privacy, offline use, no API costs |
| **Zilliz Cloud + Ollama** | Ollama + Zilliz account | Local embeddings, managed storage |
| **Zilliz Cloud + OpenAI** | API keys | Easiest setup, no local infra |

```bash
# First time: run the setup wizard
/retrieval/setup

# Index your codebase
/retrieval index

# Search semantically
/retrieval search "authentication middleware"
/retrieval search "database connection pooling"

# Check index status
/retrieval status
```

## Code Intelligence Layer

### Why This Matters

When you ask an AI coding assistant to work on a feature in a large codebase, it faces the same challenge a new developer does on their first day: *"Where do I even start?"*

Without guidance, the AI reads files at random, runs dozens of searches hoping to find relevant code, and burns through its context window (the amount of text it can "hold in memory" at once) on files that turn out to be irrelevant. This is slow, expensive, and often leads to incomplete or incorrect answers because the AI missed a critical file it didn't know to look for.

**The Code Intelligence Layer solves this by teaching the AI to navigate your codebase the way a senior developer would:**

1. **Start with the big picture.** Before diving into code, get a map of the entire repository — what files exist, what's in them, how they're organized. A senior dev would browse the folder structure and skim key files. The AI does the same via the **Repo Map + Symbol Index**.

2. **Understand relationships.** Code doesn't exist in isolation. File A imports File B, which is tested by File C. A senior dev traces these connections mentally. The AI builds a **Dependency Graph** by scanning import statements — now it knows "if I change this file, these other files are affected."

3. **Search smart, not broad.** Instead of searching the entire codebase for a keyword (which returns noise), the AI searches only within the files the map and graph identified as relevant. If semantic search is available (`/retrieval`), it finds conceptually related code even when naming conventions differ.

4. **Rank by relevance.** Not all search results are equally useful. The **Reranker** scores each result on three factors — does it match the task keywords? Is it connected to files we already care about? Is it source code (most useful) or a config file (less useful)? — and surfaces the best matches first.

5. **Assemble a focused reading list.** Instead of dumping 15+ files into context, the **Context Pack Builder** picks the top files, adds their direct dependencies and test files, and caps at 8 files total. This is the minimum context needed to understand and work on the feature — no waste.

**The result:** The AI reads fewer files, makes fewer searches, and produces better answers — because every file it reads was chosen for a reason, not found by accident.

### Impact at a Glance

| Without Code Intelligence | With Code Intelligence |
|---------------------------|----------------------|
| AI searches the entire repo blindly | AI navigates from structural overview to specific files |
| 15-20 tool calls to find relevant code | 10-13 targeted calls guided by the pipeline |
| Context window filled with irrelevant files | ≤8 precisely chosen files with dependency context |
| No understanding of file relationships | Import graph reveals what depends on what |
| All search results treated equally | 3-factor relevance scoring surfaces the best matches |
| Same overhead whether repo has 10 or 10,000 files | Smart activation — simple repos get a simple process |
| Every session starts from scratch | Repo map + symbol index persist across sessions |

### The Analogy

Think of it like GPS navigation vs. driving without a map:

- **Level 1 (Repo Map + Symbol Index)** = Satellite view of the city — you see every street and landmark at a glance
- **Level 1b (Dependency Graph)** = Knowing which roads connect to which — one-way streets, highways, dead ends
- **Level 2 (Search)** = Searching for a specific address
- **Level 2b (Reranking)** = The GPS ranking multiple routes by traffic, distance, and toll cost
- **Level 3 (Context Pack)** = The final turn-by-turn directions — exactly the roads you need, nothing extra

Without the GPS, you'd drive around guessing. With it, you take the optimal route every time.

### Technical Details

Reduce token waste and improve code reasoning with a multi-level context pipeline. Instead of searching blindly, the LLM navigates through structural overview → dependency graph → semantic search → relevance ranking → assembled context pack.

**How it works:**

```
Level 1: Repo Map + Symbol Index (≤3K tokens)
  file tree + symbols + type:name:file:line index
       │
       ▼ identifies candidates
Level 1b: Dependency Graph (repos ≥50 files)
  Grep-based import/export tracing → adjacency list
       │
       ▼ enriches with relationships
Level 2: Targeted Search
  search_code MCP (if available) or Grep/Read
       │
       ▼ raw results
Level 2b: Reranking (>5 candidates)
  keyword overlap (40%) + dep proximity (35%) + file-type (25%)
       │
       ▼ ranked results
Level 3: Context Pack (≤8 files)
  seed files + 1-hop imports + test files → progressive read depth
```

| Command | Purpose |
|---------|---------|
| `/repo-map [path]` | Generate structural overview + symbol index on demand |
| `/discover` (Step 3) | Auto-generates and embeds repo map + symbol index in `01_DISCOVERY.md` |

**Key features:**
- **5-component pipeline**: symbol index, dependency graph, semantic search, reranking, context pack builder
- **Smart activation**: dependency graph + reranking skip on small repos (<50 files); reranking skips with ≤5 candidates
- **6 language patterns**: TypeScript/JS, Python, Go, PHP, Rust + generic fallback
- **Progressive truncation**: 4 tiers by repo size — graceful degradation from full symbols → directory summaries
- **No dependencies**: Uses built-in Glob + Grep — works without MCP, Docker, or any external tools
- **8-file context pack cap**: seeds + 1-hop dependency imports + test files, with progressive read depth (full/partial/sections)
- **Session persistence**: cross-session via `01_DISCOVERY.md`; intra-session via Claude Code context window (no file cache)

```bash
# Standalone use
/repo-map                    # Full repo overview + symbol index
/repo-map src/auth           # Focused on a subdirectory

# Automatic (recommended) — runs as part of /discover
/discover Add OAuth2 login   # Repo map + symbol index auto-generated in 01_DISCOVERY.md
```

## Visualization Commands

Generate rich HTML pages from any technical content — architecture diagrams, diff reviews, project recaps, slide decks. Powered by [visual-explainer](https://github.com/nicobailon/visual-explainer). Output goes to `~/.agent/diagrams/` and opens in the browser.

| Command | Purpose |
|---------|---------|
| `/visual/generate-web-diagram [topic]` | HTML diagram for any topic — architecture, flowcharts, ER, state machines, data tables |
| `/visual/diff-review [ref]` | Visual diff review with KPI dashboard, module architecture, Good/Bad/Ugly code review |
| `/visual/plan-review [plan-file]` | Compare implementation plan against codebase — blast radius, risk assessment, gaps |
| `/visual/project-recap [time-window]` | Mental model snapshot — architecture, recent activity, decision log, cognitive debt |
| `/visual/fact-check [file]` | Verify document accuracy against actual code, correct inaccuracies in place |
| `/visual/generate-slides [topic]` | Magazine-quality slide deck with 10 slide types and 4 curated presets |
| `/visual/generate-visual-plan [feature]` | Visual implementation plan with state machines, code snippets, edge cases |
| `/visual/share [html-file]` | Deploy any HTML page to Vercel — instant public URL, no auth needed |

**SDLC touchpoints** — visualization commands pair naturally with SDLC phases:
- After `/design-system` → `/visual/generate-web-diagram` for interactive architecture diagrams
- After `/review` → `/visual/diff-review` for visual diff analysis
- After `/plan` → `/visual/plan-review` to validate the plan visually
- After `/retro` → `/visual/generate-slides` for team presentation
- Context-switching back to a project → `/visual/project-recap 2w`

## Language & Cloud Expert Commands

Auto-detected during `/discover` based on your project's tech stack:

| Command | Focus |
|---------|-------|
| `/language/typescript-pro [desc]` | Strict types, generics, branded types, discriminated unions |
| `/language/javascript-react-pro [desc]` | ES2024+, React 19, Server Components, accessibility, performance |
| `/language/php-pro [desc]` | PHP 8.2+, strict types, enums, readonly, Laravel/Symfony patterns |
| `/language/python-pro [desc]` | Python 3.11+, typing, dataclasses, Protocols, FastAPI/Django, Ruff + mypy |
| `/language/terraform-pro [desc]` | Modules, `for_each`, validation, state isolation, security, tflint/trivy |
| `/language/aws-pro [desc]` | Well-Architected, service selection, IAM, VPC, cost optimization |
| `/language/azure-pro [desc]` | Well-Architected, Managed Identity, Bicep, Entra ID, Defender |
| `/language/gcp-pro [desc]` | Architecture Framework, Workload Identity, Cloud Run, SRE practices |
| `/language/ansible-pro [desc]` | Roles, idempotency, Vault encryption, Molecule testing, dynamic inventory |
| `/language/kubernetes-pro [desc]` | Deployments, RBAC, NetworkPolicies, probes, security contexts, GitOps |
| `/language/openshift-pro [desc]` | Routes, SCCs, BuildConfigs, ImageStreams, Operators, User Workload Monitoring |
| `/language/software-engineer-pro [desc]` | **Fallback** — SOLID, clean architecture, API design, testing, refactoring (any language) |
| `/language/cloud-engineer-pro [desc]` | **Fallback** — Provider-agnostic networking, IAM, IaC, observability, DR, cost control |

## Quality Commands

Run anytime — auto-detect your stack and apply appropriate tooling:

| Command | Purpose |
|---------|---------|
| `/quality/code-audit [scope]` | Full code quality analysis — static analysis, metrics, architecture review |
| `/quality/test-strategy [scope]` | Design test pyramid, generate configs (Vitest/Pytest/PHPUnit), scaffold examples |
| `/quality/lint-setup [scope]` | Configure linter, formatter, pre-commit hooks, editor config |
| `/quality/dependency-check` | Vulnerability scan, outdated packages, license audit, bundle bloat |

---

## File Organization

```
your-project/
├── .claude/
│   ├── commands/                    # Slash commands (the workflow engine)
│   │   ├── discover.md              # Phase 1: Discovery & scoping
│   │   ├── research.md              # Phase 2: Codebase & ecosystem research
│   │   ├── design-system.md         # Phase 3: Architecture & system design
│   │   ├── plan.md                  # Phase 4: Implementation planning
│   │   ├── implement.md             # Phase 5: Code implementation
│   │   ├── review.md                # Phase 6: Code review & QA
│   │   ├── security.md              # Phase 7a: Static security audit
│   │   ├── deploy-plan.md           # Phase 9: Deployment strategy
│   │   ├── observe.md               # Phase 10: Observability setup
│   │   ├── retro.md                 # Phase 11: Retrospective
│   │   ├── ai-integrate.md          # Bonus: LLM/AI integration
│   │   ├── perf-test.md             # Bonus: Performance testing
│   │   ├── hotfix.md                # Bonus: Emergency hotfix workflow
│   │   ├── security/               # DevSecOps security sub-commands
│   │   │   ├── pentest.md          # Phase 7b: Dynamic pentest via Shannon
│   │   │   ├── redteam-ai.md       # Phase 7c: AI/LLM threat modeling
│   │   │   └── harden.md           # Phase 8: Security hardening + fix plan
│   │   ├── language/
│   │   │   ├── typescript-pro.md    # TypeScript expert mode
│   │   │   ├── javascript-react-pro.md  # JavaScript + React expert mode
│   │   │   ├── php-pro.md          # PHP expert mode
│   │   │   ├── python-pro.md       # Python expert mode
│   │   │   ├── terraform-pro.md    # Terraform / IaC expert mode
│   │   │   ├── aws-pro.md          # AWS architecture expert mode
│   │   │   ├── azure-pro.md        # Azure architecture expert mode
│   │   │   ├── gcp-pro.md          # GCP architecture expert mode
│   │   │   ├── ansible-pro.md      # Ansible automation expert mode
│   │   │   ├── kubernetes-pro.md   # Kubernetes workloads expert mode
│   │   │   ├── openshift-pro.md    # OpenShift enterprise expert mode
│   │   │   ├── software-engineer-pro.md  # Fallback: any language
│   │   │   └── cloud-engineer-pro.md     # Fallback: any cloud/infra
│   │   ├── quality/
│   │   │   ├── code-audit.md        # Full code quality analysis
│   │   │   ├── test-strategy.md     # Test pyramid setup & config
│   │   │   ├── lint-setup.md        # Linter, formatter, hooks setup
│   │   │   └── dependency-check.md  # Vulnerability & license audit
│   │   ├── visual/                    # Visualization commands (visual-explainer)
│   │   │   ├── generate-web-diagram.md  # HTML diagram generation
│   │   │   ├── diff-review.md           # Visual diff review
│   │   │   ├── plan-review.md           # Plan vs codebase visual comparison
│   │   │   ├── project-recap.md         # Mental model snapshot
│   │   │   ├── fact-check.md            # Document accuracy verification
│   │   │   ├── generate-slides.md       # Slide deck generation
│   │   │   ├── generate-visual-plan.md  # Visual implementation plan
│   │   │   └── share.md                 # Deploy HTML to Vercel
│   │   ├── n8n.md                     # n8n workflow assistant
│   │   ├── n8n/
│   │   │   └── setup.md              # n8n-MCP setup wizard
│   │   ├── firecrawl.md              # Firecrawl web scraping assistant
│   │   ├── firecrawl/
│   │   │   └── setup.md              # Firecrawl MCP setup wizard
│   │   ├── repo-map.md                # Structural repo overview (file tree + symbols)
│   │   ├── retrieval.md               # Semantic code retrieval assistant
│   │   ├── retrieval/
│   │   │   └── setup.md              # claude-context MCP setup wizard
│   │   └── devops/
│   │       └── ci-pipeline.md       # CI/CD pipeline generation
│   ├── planning/                    # Auto-generated per issue
│   │   └── {issue-name}/
│   │       ├── 00_STATUS.md            # Central progress dashboard
│   │       ├── 01_DISCOVERY.md
│   │       ├── 02_CODE_RESEARCH.md
│   │       ├── 03_ARCHITECTURE.md
│   │       ├── 03_ADR-001-*.md
│   │       ├── 03_PROJECT_SPEC.md
│   │       ├── 04_IMPLEMENTATION_PLAN.md
│   │       ├── 06_CODE_REVIEW.md
│   │       ├── 07a_SECURITY_AUDIT.md    # Phase 7a output
│   │       ├── 07b_PENTEST_REPORT.md    # Phase 7b output (Shannon)
│   │       ├── 07c_AI_THREAT_MODEL.md   # Phase 7c output (if LLMs)
│   │       ├── 08_HARDEN_PLAN.md        # Phase 8 output
│   │       ├── 09_DEPLOY_PLAN.md
│   │       ├── 10_OBSERVABILITY.md
│   │       └── 11_RETROSPECTIVE.md
│   ├── agents/                      # Multi-agent orchestration
│   │   ├── sdlc-orchestrator.md    # Autonomous SDLC agent (Research→Plan→Implement→Review)
│   │   └── security-analyst.md     # Security persona (OWASP, Shannon, OBLITERATUS)
│   ├── skills/                      # Folder-based skills (Anthropic official format)
│   │   ├── researching-code/
│   │   │   └── SKILL.md            # Codebase research skill (model: opus)
│   │   ├── planning-solutions/
│   │   │   └── SKILL.md            # Implementation planning skill (model: opus)
│   │   ├── implementing-code/
│   │   │   └── SKILL.md            # Code implementation skill (model: opus)
│   │   ├── reviewing-code/
│   │   │   └── SKILL.md            # Code review skill (model: sonnet)
│   │   ├── review-fix/
│   │   │   └── SKILL.md            # Review fix skill (model: sonnet)
│   │   ├── offensive-security/
│   │   │   └── SKILL.md            # OWASP, STRIDE, exploit patterns reference (model: opus)
│   │   └── visual-explainer/        # HTML visualization skill (visual-explainer)
│   │       ├── SKILL.md            # Workflow, diagram types, anti-slop rules (model: sonnet)
│   │       ├── references/          # CSS patterns, libraries, slide patterns (~120KB)
│   │       ├── templates/           # HTML reference templates (architecture, table, mermaid, slides)
│   │       └── scripts/share.sh    # Vercel deployment script
│   ├── LEARNINGS.md                  # Full retro learnings archive (on-demand, not always loaded)
│   ├── QUICK_REFERENCE.md           # Tool cheat sheets — terraform, docker, kubectl, ansible (on-demand)
│   ├── scripts/
│   │   └── shannon-mcp-wrapper.sh  # OAuth token wrapper for Shannon MCP server
│   └── settings.json                # Claude Code project settings + Shannon MCP config
├── CLAUDE.md                        # Project-level AI instructions (~91 lines, token-optimized)
└── docs/
    └── guides/
        ├── ai-integration-guide.md  # How to add LLM features
        └── sdlc-reference.md        # Full workflow reference
```

---

## Skills Format

Skills follow the [Anthropic official skill specification](https://docs.anthropic.com). Each skill is a folder under `.claude/skills/` with a `SKILL.md` file:

```
.claude/skills/{skill-name}/
├── SKILL.md            # Required: YAML frontmatter + instructions
└── references/         # Optional: supplementary docs (loaded on demand)
```

**SKILL.md structure:**
```yaml
---
name: skill-name          # kebab-case, matches folder name
description: "What it does. Use when [trigger]. [Capabilities]."
model: opus               # optional: sonnet, opus, haiku, inherit
metadata:
  version: 1.0.0
  category: workflow-automation
---
# Skill Title
## Goal
## Instructions
## Output Format
## Quality Check
## Common Issues
```

Skills are loaded progressively: YAML frontmatter is always in context (~100 tokens), the full SKILL.md body loads only when the skill triggers (~2K tokens), and `references/` files load on demand.

---

## Model Routing

Each phase uses a cost-appropriate model via the `model:` field in YAML frontmatter. Deep reasoning phases get Opus; checklist/template phases get Sonnet (~5x cheaper per token).

| Phase | Command | Model | Rationale |
|-------|---------|-------|-----------|
| 1. Discover | `/discover` | sonnet | Stack detection, checklist scanning |
| 2. Research | `/research` | opus | Deep architectural reasoning |
| 3. Design | `/design-system` | opus | Architecture decisions, ADRs |
| 4. Plan | `/plan` | opus | Phase sequencing, acceptance criteria |
| 5. Implement | `/implement` | opus | Multi-file code generation, testing |
| 6. Review | `/review` | sonnet | Checklist verification, pattern matching |
| 7a. Static Security | `/security` | sonnet | OWASP/STRIDE checklists |
| 7b. Dynamic Pentest | `/security/pentest` | sonnet | Shannon orchestration, report parsing |
| 7c. AI Model Audit | `/security/redteam-ai` | opus | Deep threat analysis, attack patterns |
| 8. Harden | `/security/harden` | opus | Fix plan + code patching |
| 9. Deploy | `/deploy-plan` | sonnet | Document generation from template |
| 10. Observe | `/observe` | sonnet | Document generation from template |
| 11. Retro | `/retro` | sonnet | Summarization, knowledge extraction |
| Visual: Diagram | `/visual/generate-web-diagram` | sonnet | Template-based HTML generation |
| Visual: Diff Review | `/visual/diff-review` | opus | Deep codebase analysis + visualization |
| Visual: Plan Review | `/visual/plan-review` | opus | Plan vs code cross-referencing |
| Visual: Recap | `/visual/project-recap` | opus | Architecture scan + narrative |
| Visual: Slides | `/visual/generate-slides` | sonnet | Template-based slide generation |
| Visual: Plan | `/visual/generate-visual-plan` | opus | Feature design + state machines |
| Visual: Fact Check | `/visual/fact-check` | opus | Claim extraction + source verification |

**Cost impact:** 7/11 phases on Sonnet saves ~40-60% per full SDLC run compared to running everything on Opus, with no quality loss on the checklist/template phases.

The `model:` field is officially supported in both commands and skills. Valid values: `sonnet`, `opus`, `haiku`, `inherit`.

---

## Memory & Token Optimization

The workflow includes a three-tier memory system designed to minimize always-on token cost while retaining full knowledge:

| Tier | Location | Scope | Loaded When | Est. Tokens |
|------|----------|-------|-------------|-------------|
| **Tier 0: Always-on** | `CLAUDE.md` (project) | Essential rules + 2 most recent retro blocks | Every conversation | ~300 |
| **Tier 1: On-demand repo** | `.claude/LEARNINGS.md`, `.claude/QUICK_REFERENCE.md` | Full learnings archive, tool cheat sheets | When `/retro` or commands need them | ~600 |
| **Tier 2: Project-personal** | `~/.claude/projects/{hash}/memory/` | Per-user, auto-loaded index | MEMORY.md always; topic files on demand | ~200 |

**Token savings:** The project CLAUDE.md was reduced from **555 lines to 91 lines** (~83%). Combined with a leaner global `~/CLAUDE.md` (552→98 lines), this saves **~17K tokens per conversation** — meaningful cost and latency reduction, especially on Opus.

**How it works:**
- `CLAUDE.md` (project root) — Lean: project-specific SDLC workflow rules + abbreviated 2 most recent retro blocks
- `~/CLAUDE.md` (global) — Lean: shared guidelines (repo types, security, naming, code review) — no learnings or command catalogs
- `.claude/LEARNINGS.md` — Full learnings archive from all retros, read on-demand by `/retro` and `/research`
- `.claude/QUICK_REFERENCE.md` — Tool cheat sheets (terraform, docker, kubectl, ansible, workflow), read on-demand
- `~/.claude/projects/{hash}/memory/` — Per-user auto-memory: `MEMORY.md` (index), `patterns.md`, `decisions.md`, `learnings.md`

The `/retro` command writes to all relevant tiers automatically.

---

## Recommended `settings.json` Configuration

Beyond MCP servers and permissions, `~/.claude/settings.json` accepts several flags that significantly improve day-to-day usability. Add these to take full advantage of Claude's large context window and long-running SDLC sessions:

```json
{
  "cleanupPeriodDays": 365,
  "maxTerminalOutputCharacters": 150000,
  "maxFileReadTokens": 100000,
  "autoCompactPercentageOverride": 75
}
```

| Flag | Default | Recommended | Why |
|------|---------|-------------|-----|
| `cleanupPeriodDays` | 30 | 365 | Retains conversation history for a full year — critical for long SDLC workflows |
| `maxTerminalOutputCharacters` | 30,000 | 150,000 | Handles full `terraform plan`, CI logs, and migration outputs without truncation |
| `maxFileReadTokens` | 25,000 | 100,000 | Reads large Terraform modules, PHP controllers, and generated files in full |
| `autoCompactPercentageOverride` | 95 | 75 | Triggers context compaction earlier, preserving output quality in multi-phase sessions |

### Optional: Telemetry Opt-Out

Claude Code collects Statsig telemetry, Sentry error reports, and usage feedback by default. To opt out without blocking auto-updates (unlike `--no-network`), add the following three keys — verify exact names against the Claude Code changelog as they may evolve:

```json
{
  "disableTelemetry": true,
  "disableSentryReporting": true,
  "disableFeedback": true
}
```

### Optional: Remove Co-authorship Attribution

By default, Claude appends `Co-Authored-By: Claude ...` to commits and PRs. To remove or replace with a custom string:

```json
{
  "attribution": {
    "commit": "",
    "pr": ""
  }
}
```

---

## ClaudeCTX — Profile Switcher (Recommended for Multi-Repo Workspaces)

[ClaudeCTX](https://github.com/bsyunus/claudectx) is an open-source CLI that manages separate `settings.json`, `CLAUDE.md`, MCP servers, and permissions per profile — preventing configuration bleed between contexts (e.g., infrastructure vs. frontend vs. security work).

```bash
# Install (macOS)
brew install claudectx

# Save current config as a named profile
claudectx save infra       # → ~/.claude/profiles/infra/

# Switch profiles (auto-backs up current state before switching)
claudectx infra            # restores ~/.claude/profiles/infra/ → ~/.claude/
claudectx frontend
claudectx security
```

Profiles live in `~/.claude/profiles/<name>/` and include `settings.json`, `CLAUDE.md`, and MCP server configs.

**Suggested profiles for this workflow:**

| Profile | Expert commands enabled | MCP servers |
|---------|------------------------|-------------|
| `infra` | terraform-pro, ansible-pro, kubernetes-pro | Shannon, claude-context |
| `app` | typescript-pro, php-pro, python-pro | Firecrawl, n8n, claude-context |
| `security` | software-engineer-pro | Shannon, OBLITERATUS |

---

## 00_STATUS.md — Your Progress Dashboard

Every command reads and updates `00_STATUS.md`. It is the single source of truth.

```markdown
# Status: add-realtime-collab

**Risk:** High | **Updated:** 2026-02-21 3:00 PM

## Progress
- [x] Discovery - Completed (scope: WebSocket-based OT)
- [x] Research - Completed (identified conflict resolution patterns)
- [x] Design - Completed (ADR-001: chose CRDT over OT)
- [x] Planning - Completed (4 phases, 12 tasks)
- [~] Implementation - In Progress (Phase 2/4)
- [ ] Review - Not started
- [ ] Security - Not started
- [ ] Deploy - Not started
- [ ] Observe - Not started
- [ ] Retro - Not started

## Key Decisions
- ADR-001: CRDT over OT for conflict resolution (latency vs complexity tradeoff)
- ADR-002: WebSocket with fallback to SSE for transport

## Artifacts
- 01_DISCOVERY.md, 02_CODE_RESEARCH.md, 03_ARCHITECTURE.md
- 03_ADR-001-conflict-resolution.md, 03_ADR-002-transport.md
- 03_PROJECT_SPEC.md, 04_IMPLEMENTATION_PLAN.md
```

---

## Stack Auto-Detection

The `/discover` command automatically scans your project to detect:

**Languages:** TypeScript, JavaScript, PHP, Python, Rust, Go, Ruby — by checking for `tsconfig.json`, `package.json`, `composer.json`, `pyproject.toml`, etc.

**Frameworks:** Next.js, Nuxt, Angular, Vue, Django, FastAPI, Flask, Laravel, Symfony — by inspecting dependency manifests.

**Cloud/Infra:** AWS, Azure, GCP, Terraform, Docker, Kubernetes — by scanning for `.tf` files, `*.bicep`, CDK configs, Dockerfiles, etc.

**Quality Tooling:** ESLint, Prettier, Vitest/Jest, PHPStan, Ruff, pre-commit hooks, CI/CD pipelines — reports what's configured and what's missing.

This detection feeds into `01_DISCOVERY.md` and `00_STATUS.md`, so every subsequent phase knows which expert commands (`/language/*-pro`) and quality commands (`/quality/*`) are relevant. If quality tooling gaps are found, the discovery phase recommends fixing them before proceeding to implementation.

Additionally, `/discover` now auto-generates a **Repository Map + Symbol Index** (Step 3) — a compact structural overview (file tree + symbols, ≤2K tokens) plus a structured symbol index (`type:name:file:line`, ≤1K tokens) embedded directly in `01_DISCOVERY.md`. These power the Code Intelligence Layer in `/research`: dependency graph building, 3-factor relevance reranking, and context pack assembly (≤8 files), ensuring the LLM navigates to the most relevant files instead of searching blindly.

---

## Complete Workflow Example

```bash
# Phase 1: Discover — define scope and generate issue name
/discover Add JWT authentication with refresh tokens and role-based access control

# Output: issue name "add-jwt-rbac", 01_DISCOVERY.md, 00_STATUS.md
# STATUS: [x] Discovery | [ ] Research | ...

# Phase 2: Research — deep-dive into codebase and ecosystem
/research add-jwt-rbac

# Output: 02_CODE_RESEARCH.md (existing auth patterns, deps, risks)
# STATUS: [x] Discovery | [x] Research | [ ] Design | ...

# Phase 3: Design — architecture, ADRs, system spec
/design-system add-jwt-rbac

# Output: 03_ARCHITECTURE.md, 03_ADR-001-token-strategy.md, 03_PROJECT_SPEC.md
# STATUS: [x] Discovery | [x] Research | [x] Design | ...

# Phase 4: Plan — detailed implementation plan with phases and tasks
/plan add-jwt-rbac

# Output: 04_IMPLEMENTATION_PLAN.md (4 phases, test strategy)
# STATUS: [x] Discovery | [x] Research | [x] Design | [x] Planning | ...

# Phase 5: Implement — write code phase by phase
/implement add-jwt-rbac

# STATUS: [~] Implementation (Phase 2/4) → [x] Implementation (12 files, 47 tests)

# Phase 6: Review — comprehensive code review and QA
/review add-jwt-rbac

# Output: 06_CODE_REVIEW.md
# STATUS: [x] Review - ✓ APPROVED

# Phase 7a: Static security audit
/security add-jwt-rbac

# Output: 07a_SECURITY_AUDIT.md (threat model, dependency scan, OWASP checklist)
# STATUS: [x] Static Security - ⚠ CONDITIONAL PASS (2 findings need dynamic testing)

# Phase 7b: Dynamic pentest (optional — requires staging environment)
/security/pentest add-jwt-rbac

# Output: 07b_PENTEST_REPORT.md (Shannon confirmed 1 exploit, dismissed 1 as non-exploitable)
# STATUS: [x] Dynamic Pentest - 1 confirmed vulnerability (JWT alg:none bypass)

# Phase 7c: AI model audit (only if your feature uses an LLM)
# /security/redteam-ai add-jwt-rbac  # ← skip if no LLM components

# Phase 8: Harden — fix confirmed vulnerabilities
/security/harden add-jwt-rbac

# Output: 08_HARDEN_PLAN.md (P0: JWT fix implemented, P2: 1 GitHub issue created)
# STATUS: [x] Hardening - P0 fixes applied, regression tests passing

# Phase 9: Deploy
/deploy-plan add-jwt-rbac

# Output: 09_DEPLOY_PLAN.md (rollout strategy, feature flags, rollback)

# Phase 10: Observe
/observe add-jwt-rbac

# Output: 10_OBSERVABILITY.md (metrics, alerts, dashboard specs)

# Phase 11: Retro
/retro add-jwt-rbac

# Output: 11_RETROSPECTIVE.md, updates to CLAUDE.md with learnings
# STATUS: ALL PHASES COMPLETE ✓
```

---

## When to Skip Phases

Not every change needs all phases. Use judgment:

| Change Type | Recommended Phases |
|---|---|
| Typo fix | Just fix it directly |
| Small bug fix | Research → Implement → Review |
| Medium feature | Discover → Research → Plan → Implement → Review |
| Large feature | All phases |
| Security-critical | All phases, include 7b Pentest + 8 Harden |
| Hotfix/emergency | `/hotfix` (compressed: Research → Fix → Review → Deploy) |
| AI/LLM feature | Add `/ai-integrate` between Design and Plan, include 7c AI Audit |
| Auth/payment/PII | Must include 7a + 7b + 8 (static + dynamic + harden) |

---

## Parallel Feature Development

```bash
# Start two features simultaneously
/discover Add OAuth2 authentication        # → generates: add-oauth-auth
/discover Fix memory leak in data pipeline  # → generates: fix-data-pipeline-leak

# Each gets its own directory and 00_STATUS.md
.claude/planning/add-oauth-auth/00_STATUS.md
.claude/planning/fix-data-pipeline-leak/00_STATUS.md

# Continue each workflow independently
/research add-oauth-auth
/research fix-data-pipeline-leak
```

---

## CLAUDE.md — Token-Optimized Project Intelligence

The `CLAUDE.md` files are designed to minimize always-on token cost. The project CLAUDE.md contains only essential workflow rules (~91 lines), while reference material lives in on-demand files:

```
CLAUDE.md (project root, ~91 lines)     ← Always loaded: SDLC workflow, session checks, 2 recent retro blocks
~/CLAUDE.md (global, ~98 lines)          ← Always loaded: shared repo guidelines, security, naming
.claude/LEARNINGS.md                     ← On-demand: full retro learnings archive
.claude/QUICK_REFERENCE.md              ← On-demand: terraform, docker, kubectl, ansible cheat sheets
```

The `/retro` command writes **abbreviated** learnings to CLAUDE.md (max 2 recent blocks) and **full detail** to `.claude/LEARNINGS.md`. Older blocks are automatically rotated out of CLAUDE.md to keep the token budget lean.

---

## Credits

This project synthesizes and extends:

- **[claude-code-ai-development-workflow](https://github.com/DenizOkcu/claude-code-ai-development-workflow)** by DenizOkcu — the original 4-phase slash command workflow (Research → Plan → Execute → Review)
- **[llm-knowledge-hub](https://github.com/OmarKAly22/llm-knowledge-hub)** by OmarKAly22 — comprehensive LLM development guides, agentic AI patterns, RAG, security, evaluation, and best practices
- **[Shannon](https://github.com/KeygraphHQ/shannon)** by KeygraphHQ — autonomous AI pentester for dynamic security testing
- **[OBLITERATUS](https://github.com/elder-plinius/OBLITERATUS)** by elder-plinius — mechanistic interpretability toolkit for AI model alignment analysis
- **[visual-explainer](https://github.com/nicobailon/visual-explainer)** by nicobailon — rich HTML visualization engine with Mermaid diagrams, interactive zoom/pan, slide decks, and anti-AI-slop design guardrails

Extended with: Discovery, Architecture/ADR, DevSecOps security layer (static + dynamic + AI audit + hardening), Deployment, Observability, Retrospective phases, Visualization layer, AI/LLM integration commands, performance testing, hotfix workflow, multi-agent orchestration patterns, and self-improving CLAUDE.md via automated retrospectives.

## License

MIT
