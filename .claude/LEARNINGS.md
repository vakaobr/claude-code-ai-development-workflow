# Learnings (auto-updated by /retro)
<!-- The /retro command appends lessons learned here automatically -->

### 2026-06-11 — add-markitdown-conversion

- **A `PreToolUse(Read)` hook only fires on *model-initiated* `Read` tool calls.** Files a user drags/drops or pastes as a bare path are attached by Claude Code *before* any hook runs, bypassing the interceptor entirely. There is **no hook event** (`PreToolUse`, `UserPromptSubmit`, etc.) that intercepts the file-attachment pipeline. "Auto-convert any dropped file before Claude sees it" is therefore not achievable with current hooks — set expectations and route dropped docs via an explicit command (`/markitdown convert <path>`).
- **Hooks run headless via `sh -c` with a minimal PATH and must fail open.** Always: (1) prepend an explicit `PATH` (`/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin`) so `jq`/`stat`/venv binaries resolve; (2) `exit 0` on any miss/error so the tool proceeds; (3) add a toggleable debug log (off by default) — without it you cannot distinguish "hook not invoked" from "invoked but errored."
- **"Applies everywhere" hooks belong at user-level (`~/.claude/settings.json` + `~/.claude/hooks/` + absolute command paths), not project-level.** A project-scoped hook silently does nothing in other repos. Decide global-vs-project at design time, and ship a reproducible installer for the user-level pieces (venv + hook + registration) so a clean clone can recreate them.
- **`markitdown-mcp` (alpha `0.0.1a4`) requires Python 3.10–3.13** — 3.14 fails because `markitdown[all]` → `youtube-transcript-api~=1.0.0` has no 3.14 wheel. It also hard-pins `mcp~=1.8.0`, whose CVEs are HTTP-transport DoS — **not reachable by a STDIO-only local server**, so pin and accept rather than force-upgrade (which breaks the pin).
- **`gh pr create` on a fork defaults the base to the upstream repo.** Symptom: GraphQL "Head/Base sha can't be blank / No commits between." Fix: `gh pr create --repo <your-user>/<repo> --base main --head <branch>`. Also: repo rulesets that block force-push *and* branch deletion force a fresh-branch + cleanup-commit workflow; delete stale branches via the GitHub UI.
- **`git checkout <ref> -- <file>` silently stages that file.** It then gets swept into the next commit (it leaked `settings.json` into a docs commit and the PR). Always `git diff --cached --name-only` before committing; stage feature files explicitly, never rely on a clean index.

### 2026-03-15 — add-repo-context-engine

- **Embed mandatory workflow tools in existing phase entry points, not as optional standalone commands.** Users follow the happy path — they won't run `/repo-map` manually, but they will run `/discover`. Integrate the tool into the phase they already use.
- **For prompt-engineering projects, CLAUDE.md updates belong in the implementation phase, not the deploy phase.** Deferring them means they get forgotten. Add "update CLAUDE.md" as an explicit task in the implementation acceptance criteria for any workflow tooling change.
- **Exclusion lists that exist in multiple prompt files will drift.** If two commands need the same exclusion list (e.g., `repo-map.md` and `discover.md`), add a cross-reference note to one pointing to the other as canonical. Prevents silent divergence over time.
- **Progressive truncation with named tiers (< 100 / 100–200 / 200–500 / > 500 files) is better than a hard token cutoff for LLM output budget management.** Hard cutoffs lose structural information unpredictably; tiered degradation (symbols → files → directories → summary) preserves the most useful information at each tier.
- **The Design phase can be skipped for M-sized prompt-only changes; the Observe phase is always skippable for prompt-only changes.** No metrics, dashboards, or alerting to configure. But the Security phase (7a) is still valuable even with no runtime code — STRIDE analysis reliably catches prompt injection and artifact tampering risks.

### 2026-03-15 — add-semantic-retrieval

- **Pin MCP server versions in setup wizard config blocks** (`@0.1.6`, not `@latest`). `@latest` is convenient but creates supply chain risk — a compromised update is silently fetched on next session start. The setup wizard should pin with a comment explaining how to upgrade.
- **Docker `-p PORT:PORT` binds to `0.0.0.0` by default** — network-accessible from all interfaces. Always use `-p 127.0.0.1:PORT:PORT` in setup wizard Docker commands for local dev tooling. Caught via STRIDE network-listener analysis.
- **Ollama embedding dimension auto-detection is unreliable for batch processing** (issue #235). Always set `EMBEDDING_DIMENSION` explicitly (e.g., `768` for nomic-embed-text) and keep `EMBEDDING_BATCH_SIZE=5` when configuring MCP servers with Ollama.
- **Milvus Lite (in-process SQLite) is Python-only** — the Node.js SDK (`@zilliz/milvus2-sdk-node`) does not support it. If an MCP package depends on Milvus in Node.js, Docker is the minimum for local operation. Validate embedded-mode availability per runtime during research.
- **The implicit feature flag pattern (MCP config presence) is the right default for optional enhancements.** No code-level flag needed; the feature is off unless the user runs `/setup`. Session-start checks close the discoverability gap without forcing adoption.

### 2026-03-15 — optimize-token-usage

- **Measure token cost before optimizing.** Line count × ~3.5 gives a rough token estimate for markdown. Two CLAUDE.md files totalling 1,108 lines ≈ 18K tokens loaded every conversation is the baseline to beat.
- **"Always-on" vs "on-demand" is the key split for CLAUDE.md content.** Behavioral rules belong always-on. Reference material (cheat sheets, historical learnings, command catalogs) should be on-demand — readable by commands when needed, not injected into every conversation.
- **Deduplication of global + project CLAUDE.md is a one-time win with compounding savings.** Every conversation in a repo with both files loaded pays the duplication tax. Global file = universal behavioral rules. Project file = project-specific workflow only. Zero overlap.
- **A `/retro` rotation rule prevents CLAUDE.md learnings from bloating.** Constraint: keep only 2 most recent retro blocks in CLAUDE.md; full history in `.claude/LEARNINGS.md`. The file never grows past ~120 lines in the Learnings section regardless of retro count.
- **Quick-reference command cheat sheets (terraform, kubectl, etc.) don't belong in CLAUDE.md.** They're consulted rarely but loaded every conversation. Move to `.claude/QUICK_REFERENCE.md` and add a one-liner pointer.
- **Run `/retro` even for conversational (non-SDLC) changes.** Lessons from ad-hoc improvements are as valuable as formal SDLC retros. The right abbreviated workflow for prompt-only tooling changes is: analyze → implement directly → retro (skip Discovery, Design, Observe).

### 2026-03-15 — add-code-intelligence-layer

- **Template placeholders require a paired generation instruction in the step that produces the data.** A placeholder in the `01_DISCOVERY.md` template (`## Symbol Index`) is silent if the Step 3 generation instructions don't explicitly invoke symbol index generation. Caught by code review; fix: add the instruction in the generation step, not just the template.
- **Multi-level activation conditions keep skill pipelines fast on trivial inputs.** Use `if repo >= N files` and `if candidates > M` gates to skip expensive steps (dependency graph, reranking) on small repos. The pipeline enriches only when enrichment can help.
- **Compact `type:name:file:line` format is ~5x more token-efficient than human-readable tables for LLM-consumed structured data.** Use compact formats for any data embedded in planning artifacts that downstream LLMs will parse.
- **The context window IS the intra-session cache.** Don't add `.claude/cache/` directories for intermediate LLM computation results — ephemeral state (dependency graph, reranked list) lives in the context window naturally; only cross-session state (symbol index) needs file persistence.

### 2026-02-28 — add-memory-improve-skills

- **The `model:` frontmatter field is officially supported in Claude Code skills and commands (values: `sonnet`, `opus`, `haiku`, `inherit`).** Use it for cost-optimized model routing: Opus for deep reasoning phases (research, design, plan, implement), Sonnet for checklist/template phases (discover, review, security, deploy, observe, retro). Saves ~40-60% on a full SDLC run.
- **Always audit `~/.claude/` before deploying changes that touch the Claude Code environment.** Preserve: `settings.json` (permissions, model), `plugins/` (installed plugins), `claude_desktop_config.json` (MCP servers), existing `memory/` files. These are user-specific and silently lost if overwritten.
- **Non-destructive migration: create alongside, verify, then delete.** For file restructuring, create new structure first, verify it works, then remove old files. Provides safe rollback at every step.
- **Cross-reference audits must include `docs/` and archive paths.** `docs/integration-plan.md` had 7 stale skill file paths. Always grep the full repo, not just `.claude/`.
- **Verify YAML field support against official docs before removing fields.** We removed `model: sonnet` from skills based on incomplete information, then had to re-add it. Check the Claude Code spec first.
