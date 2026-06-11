#!/usr/bin/env bash
# =============================================================================
# markitdown-mcp-wrapper.sh
#
# Single launch source of truth for the MarkItDown MCP server (ADR-002).
# Resolves a Python runner at startup in priority order and execs the
# `markitdown-mcp` server over STDIO. This survives the common case where
# `uvx` is not installed and shields the launch from pyenv shim drift.
#
# Runner priority ladder (must stay in sync with /markitdown/setup wizard):
#   1. uvx --from markitdown-mcp==<pin> markitdown-mcp — zero-install, isolated
#   2. pipx run --spec markitdown-mcp==<pin> markitdown-mcp — isolated
#   3. project venv console-script — .claude/.venvs/markitdown/bin/markitdown-mcp
#      (created by /markitdown/setup when it installs via pip)
#   4. markitdown-mcp on PATH    — last-resort (global pip install)
#   5. error → point user at /markitdown/setup
#
# Version is pinned (Security R3 / 07a A06) — re-pin on upgrade, keep in sync
# with the wizard. The venv/PATH paths inherit whatever the wizard pinned.
#
# Usage (called automatically by Claude Code via settings.json):
#   bash .claude/scripts/markitdown-mcp-wrapper.sh
#
# Manual test:
#   bash .claude/scripts/markitdown-mcp-wrapper.sh   # with no runner → exits 1
# =============================================================================

set -euo pipefail

# Pinned version (Security R3). Keep in sync with /markitdown/setup.
MD_MCP_PIN="markitdown-mcp==0.0.1a4"

log() { echo "[markitdown-mcp-wrapper] $*" >&2; }

# Resolve the project venv console script relative to this wrapper's location,
# so it works regardless of the caller's working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_BIN="${SCRIPT_DIR}/../.venvs/markitdown/bin/markitdown-mcp"

# ---------------------------------------------------------------------------
# Runner ladder — first match wins
# ---------------------------------------------------------------------------
if command -v uvx >/dev/null 2>&1; then
  log "Launching via uvx (pinned $MD_MCP_PIN)"
  exec uvx --from "$MD_MCP_PIN" markitdown-mcp "$@"
fi

if command -v pipx >/dev/null 2>&1; then
  log "Launching via pipx run (pinned $MD_MCP_PIN)"
  exec pipx run --spec "$MD_MCP_PIN" markitdown-mcp "$@"
fi

if [[ -x "$VENV_BIN" ]]; then
  log "Launching via project venv: $VENV_BIN"
  exec "$VENV_BIN" "$@"
fi

if command -v markitdown-mcp >/dev/null 2>&1; then
  log "Launching via markitdown-mcp on PATH"
  exec markitdown-mcp "$@"
fi

# ---------------------------------------------------------------------------
# No runner found
# ---------------------------------------------------------------------------
log "ERROR: no MarkItDown runner found (tried uvx, pipx, project venv, PATH)."
log "Run /markitdown/setup to install the server, then restart Claude Code."
exit 1
