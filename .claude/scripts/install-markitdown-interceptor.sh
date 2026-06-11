#!/usr/bin/env bash
# =============================================================================
# install-markitdown-interceptor.sh
#
# Reproducibly installs the USER-LEVEL auto-conversion interceptor so it works
# in every Claude Code project (not just this repo). Run once after cloning:
#
#   bash .claude/scripts/install-markitdown-interceptor.sh
#
# It installs three things into ~/.claude:
#   1. A Python venv at ~/.claude/.venvs/markitdown  (markitdown-mcp pinned)
#   2. The hook script   ~/.claude/hooks/markitdown-read.sh   (copied from repo)
#   3. A PreToolUse(Read) hook registered in ~/.claude/settings.json
#
# After install: RESTART Claude Code, then run /hooks to confirm.
#
# Behavior once active: when Claude calls the Read tool on a document
# (.pdf/.docx/.doc/.pptx/.ppt/.xlsx/.xls/.epub), the hook converts it locally to
# a sibling <name>.converted.md and redirects the read there — BEFORE the binary
# is loaded, so no tokens are spent on it. Images/audio are left untouched.
#
# Known limitation: files DRAGGED-DROPPED or pasted as a bare path are attached
# by Claude Code before any hook runs, so they bypass this. For those, ask
# "read <path>" or use /markitdown convert <path>.
#
# Idempotent: safe to re-run (skips an existing venv, re-copies the hook, and
# only adds the settings entry if missing).
# =============================================================================

set -euo pipefail

PIN="markitdown-mcp==0.0.1a4"   # keep in sync with markitdown-mcp-wrapper.sh + /markitdown/setup
REPO_HOOK="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/hooks/markitdown-read.sh"
DEST_HOOK="$HOME/.claude/hooks/markitdown-read.sh"
VENV="$HOME/.claude/.venvs/markitdown"
SETTINGS="$HOME/.claude/settings.json"

log() { echo "[install-markitdown-interceptor] $*"; }

# --- 1. find a compatible Python (3.10–3.13; 3.14 breaks youtube-transcript-api) ---
find_python() {
  local c v
  for c in python3.13 python3.12 python3.11 python3.10; do
    command -v "$c" >/dev/null 2>&1 && { echo "$c"; return 0; }
  done
  if [[ -d "$HOME/.pyenv/versions" ]]; then
    for v in "$HOME"/.pyenv/versions/3.13.* "$HOME"/.pyenv/versions/3.12.* \
             "$HOME"/.pyenv/versions/3.11.* "$HOME"/.pyenv/versions/3.10.*; do
      [[ -x "$v/bin/python3" ]] && { echo "$v/bin/python3"; return 0; }
    done
  fi
  if command -v python3 >/dev/null 2>&1 && \
     python3 -c 'import sys; sys.exit(0 if (3,10)<=sys.version_info<(3,14) else 1)' 2>/dev/null; then
    echo python3; return 0
  fi
  return 1
}

if ! PY="$(find_python)"; then
  log "ERROR: need Python 3.10–3.13 (3.14 is unsupported by markitdown's deps)."
  log "Install one, e.g.:  pyenv install 3.12  (or  brew install python@3.12)"
  exit 1
fi
log "Using Python: $PY ($("$PY" --version 2>&1))"

# --- 2. venv + pinned install (idempotent) ---------------------------------
if [[ ! -x "$VENV/bin/markitdown" ]]; then
  log "Creating venv at $VENV"
  "$PY" -m venv "$VENV"
  "$VENV/bin/pip" install --upgrade pip --quiet
  log "Installing $PIN (pulls markitdown[all]) — this can take a minute…"
  "$VENV/bin/pip" install "$PIN" --quiet
  log "Tip: scan deps with  $VENV/bin/pip install pip-audit && $VENV/bin/pip-audit"
else
  log "venv already present at $VENV — skipping install"
fi

# --- 3. copy hook script ----------------------------------------------------
mkdir -p "$HOME/.claude/hooks"
cp "$REPO_HOOK" "$DEST_HOOK"
chmod +x "$DEST_HOOK"
log "Installed hook script → $DEST_HOOK"

# --- 4. register PreToolUse(Read) hook in ~/.claude/settings.json (safe merge) ---
mkdir -p "$HOME/.claude"
RESULT="$("$PY" - "$SETTINGS" "$DEST_HOOK" <<'PYEOF'
import json, os, sys
settings_path, hook_cmd = sys.argv[1], sys.argv[2]
data = {}
if os.path.exists(settings_path):
    with open(settings_path) as f:
        data = json.load(f)
grp = None
pre = data.setdefault("hooks", {}).setdefault("PreToolUse", [])
for g in pre:
    if g.get("matcher") == "Read":
        grp = g
        break
if grp is None:
    grp = {"matcher": "Read", "hooks": []}
    pre.append(grp)
cmds = grp.setdefault("hooks", [])
if any(h.get("command") == hook_cmd for h in cmds):
    print("already-registered")
else:
    cmds.append({"type": "command", "command": hook_cmd, "timeout": 600})
    with open(settings_path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("registered")
PYEOF
)"
log "PreToolUse(Read) hook: $RESULT in $SETTINGS"

# --- 5. verify --------------------------------------------------------------
if "$VENV/bin/markitdown-mcp" --help >/dev/null 2>&1; then
  log "markitdown server binary OK"
fi

cat <<EOF

✅ Auto-conversion interceptor installed.

   1. RESTART Claude Code (hooks load at startup).
   2. Run /hooks — confirm 'PreToolUse → Read → $DEST_HOOK'.

   Then: when Claude reads a .pdf/.docx/.pptx/.xlsx/.epub it is auto-converted
   to a sibling .converted.md (no tokens spent on the binary).

   Dragged-in / pasted-path files bypass the hook (Claude Code attaches them
   before any hook runs) — for those, ask "read <path>" or run
   /markitdown convert <path>.
EOF
