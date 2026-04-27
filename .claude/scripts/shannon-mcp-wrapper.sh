#!/usr/bin/env bash
# =============================================================================
# shannon-mcp-wrapper.sh
#
# Dynamically reads the Claude Code OAuth token from the local credentials
# file and injects it as CLAUDE_CODE_OAUTH_TOKEN before starting the Shannon
# MCP server.  This means you never have to manually copy/paste a token or
# update a .env file when the session rotates.
#
# Usage (called automatically by Claude Code via settings.json):
#   ./scripts/shannon-mcp-wrapper.sh
#
# Manual test:
#   SHANNON_DIR=/path/to/shannon ./scripts/shannon-mcp-wrapper.sh
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# 1+2. Load Claude credentials and extract the OAuth token.
#
# On macOS, Claude Code stores credentials in the login keychain under
# "Claude Code-credentials". On Linux, it falls back to ~/.claude/credentials.json.
# ---------------------------------------------------------------------------
CRED_JSON=""

if [[ "$(uname -s)" == "Darwin" ]]; then
  CRED_JSON=$(security find-generic-password -s "Claude Code-credentials" -w 2>/dev/null || true)
fi

if [[ -z "$CRED_JSON" ]]; then
  CLAUDE_CREDENTIALS_FILE="${HOME}/.claude/credentials.json"
  if [[ -f "$CLAUDE_CREDENTIALS_FILE" ]]; then
    CRED_JSON=$(cat "$CLAUDE_CREDENTIALS_FILE")
  fi
fi

if [[ -z "$CRED_JSON" ]]; then
  echo "[shannon-mcp-wrapper] ERROR: Claude credentials not found." >&2
  echo "[shannon-mcp-wrapper] Looked in macOS Keychain (service 'Claude Code-credentials') and ${HOME}/.claude/credentials.json." >&2
  echo "[shannon-mcp-wrapper] Run 'claude login' to authenticate." >&2
  exit 1
fi

OAUTH_TOKEN=$(CRED_JSON="$CRED_JSON" python3 -c "
import json, os, sys
try:
    data = json.loads(os.environ['CRED_JSON'])
    token = (
        data.get('claudeAiOauth', {}).get('accessToken') or
        data.get('oauthToken') or
        data.get('accessToken') or
        data.get('token')
    )
    print(token or 'NOT_FOUND', end='')
except Exception as e:
    print('ERROR:' + str(e), end='')
" 2>/dev/null)

if [[ -z "$OAUTH_TOKEN" || "$OAUTH_TOKEN" == "NOT_FOUND" ]]; then
  echo "[shannon-mcp-wrapper] ERROR: Could not extract OAuth token from credentials." >&2
  echo "[shannon-mcp-wrapper] Try 'claude login' to refresh credentials." >&2
  exit 1
fi

if [[ "$OAUTH_TOKEN" == ERROR:* ]]; then
  echo "[shannon-mcp-wrapper] ERROR parsing credentials: ${OAUTH_TOKEN}" >&2
  exit 1
fi

echo "[shannon-mcp-wrapper] OAuth token loaded successfully (length: ${#OAUTH_TOKEN})" >&2

# ---------------------------------------------------------------------------
# 3. Locate the Shannon MCP server
# ---------------------------------------------------------------------------
# Allow override via environment variable
SHANNON_DIR="${SHANNON_DIR:-}"

if [[ -z "$SHANNON_DIR" ]]; then
  # Common locations to search
  CANDIDATES=(
    "./shannon"
    "../shannon"
    "${HOME}/shannon"
    "${HOME}/projects/shannon"
  )
  for candidate in "${CANDIDATES[@]}"; do
    if [[ -f "${candidate}/mcp-server/package.json" ]]; then
      SHANNON_DIR="$(realpath "$candidate")"
      break
    fi
  done
fi

if [[ -z "$SHANNON_DIR" || ! -f "${SHANNON_DIR}/mcp-server/package.json" ]]; then
  echo "[shannon-mcp-wrapper] ERROR: Shannon MCP server not found." >&2
  echo "[shannon-mcp-wrapper] Set SHANNON_DIR=/path/to/shannon in your environment or settings.json." >&2
  echo "[shannon-mcp-wrapper] Expected: \$SHANNON_DIR/mcp-server/package.json" >&2
  exit 1
fi

MCP_SERVER_DIR="${SHANNON_DIR}/mcp-server"
echo "[shannon-mcp-wrapper] Using Shannon at: $SHANNON_DIR" >&2

# ---------------------------------------------------------------------------
# 4. Build the MCP server if dist/ is missing
# ---------------------------------------------------------------------------
if [[ ! -d "${MCP_SERVER_DIR}/dist" ]]; then
  echo "[shannon-mcp-wrapper] Building Shannon MCP server (first run)..." >&2
  cd "$MCP_SERVER_DIR"
  npm install --silent
  npm run build --silent
  cd - > /dev/null
  echo "[shannon-mcp-wrapper] Build complete." >&2
fi

# ---------------------------------------------------------------------------
# 5. Export credentials and launch the MCP server
# ---------------------------------------------------------------------------
export CLAUDE_CODE_OAUTH_TOKEN="$OAUTH_TOKEN"

# Unset API key to avoid conflicts — OAuth takes precedence
unset ANTHROPIC_API_KEY 2>/dev/null || true

echo "[shannon-mcp-wrapper] Starting Shannon MCP server..." >&2

exec node "${MCP_SERVER_DIR}/dist/index.js" "$@"
