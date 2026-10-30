# Vendored EGM root (managed by scripts/sync-egm.py)

This folder contains files from the Elephant-Goldfish Model (EGM),
https://github.com/google/elephant-goldfish-model, Copyright 2026 Google LLC, licensed under the
Apache License 2.0 (see `LICENSE` in this folder). EGM is not an officially
supported Google product.

- Upstream commit: `480881adc9a9f350e3b3f18a86a249eefd92968b` (plugin version 0.1.0)
- Vendored on: 2026-10-30
- Synced by: `scripts/sync-egm.py --ref 480881adc9a9f350e3b3f18a86a249eefd92968b`

## Files in this folder

Copied unmodified from upstream: `agents`, `resources`, `docs`, `skills`, `LICENSE`, `README.md`, `TESTING.md`
(from `docs/`, only claude.md, codex.md, getting_started.md, harnesses.md, privacy.md).

## Modified copies outside this folder

- `agents/{egm-bootstrap-orchestrator.md,egm-codebase-details.md,egm-comprehension.md,egm-design.md,egm-implementation-readiness.md,egm-structural.md,egm-style.md,egm-synthesizer.md,egm-zoom-out.md}`: upstream `.claude-plugin/agents/*.md`
  with `${CLAUDE_PLUGIN_ROOT}` replaced by `<EGM root>`.
- `skills/{egm-review,egm-review-loop,egm-brainstorm,egm-draft,egm-resolve,egm-bootstrap}`: upstream `skills/<name>/` with
  `${CLAUDE_PLUGIN_ROOT}` and `../../` replaced by `<EGM root>`, the `egm:`
  agent namespace removed, and a header in each `SKILL.md` naming this commit.

No reviewer persona, standard or review protocol text was changed.
