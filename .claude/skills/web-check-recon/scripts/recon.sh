#!/usr/bin/env bash
# One-shot driver for web-check-recon. Runs the WHOLE pipeline so the
# operator (or the skill) issues a single command instead of four:
#
#   recon.sh <target> <tier> <planning_dir> [options]
#     target         in-scope hostname (no scheme), e.g. app.example.com
#     tier           passive | active   (the CALLER must have scope-gated this)
#     planning_dir   .claude/planning/{issue}
#
#   Options:
#     --keep-up      leave the container running after the run
#     --tls-labs     also run the public Qualys SSL Labs scan (scope-approved only)
#     --rps N        request spacing (default 4)
#     --no-pull      skip the image pull (offline / already-pulled)
#
# Pipeline: pull (once) -> up (health-gated) -> run checks -> normalize
#           -> down (unless --keep-up).
#
# NB: scope authorization + tier selection happen BEFORE this script, in
# the skill (it reads .claude/security-scope.yaml). This script trusts the
# tier it is given and never widens it.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # scripts/

TARGET="${1:-}"; TIER="${2:-}"; PLANNING="${3:-}"
if [[ -z "$TARGET" || -z "$TIER" || -z "$PLANNING" ]]; then
  echo "usage: recon.sh <target> <tier:passive|active> <planning_dir> [--keep-up] [--tls-labs] [--rps N] [--no-pull]" >&2
  exit 2
fi
shift 3

KEEP_UP=0; DO_PULL=1; RPS=4; export INCLUDE_TLS_LABS=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-up)  KEEP_UP=1 ;;
    --tls-labs) export INCLUDE_TLS_LABS=1 ;;
    --no-pull)  DO_PULL=0 ;;
    --rps)      RPS="${2:?--rps needs a value}"; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

RAW="$PLANNING/webcheck/raw"
mkdir -p "$RAW"

step() { printf '\n=== %s ===\n' "$1"; }

cleanup() {
  if [[ "$KEEP_UP" -eq 0 ]]; then
    step "Teardown"
    bash "$HERE/webcheck-up.sh" down || true
  else
    echo "(--keep-up) container left running at http://127.0.0.1:3000"
  fi
}
trap cleanup EXIT

if [[ "$DO_PULL" -eq 1 ]]; then
  step "Pull image (idempotent)"
  bash "$HERE/webcheck-up.sh" pull || echo "pull skipped/failed - continuing (cached image may exist)"
fi

step "Start instance"
bash "$HERE/webcheck-up.sh" up

step "Run checks (tier=$TIER, rps=$RPS, tls-labs=$INCLUDE_TLS_LABS)"
RATE_LIMIT_RPS="$RPS" bash "$HERE/run-webcheck.sh" "$TARGET" "$TIER" "$RAW"

step "Normalize"
python3 "$HERE/normalize.py" --raw "$RAW" --target "$TARGET" --out "$PLANNING"

step "Done"
echo "Artifacts in $PLANNING:"
echo "  - WEBCHECK.md"
echo "  - PASSIVE_RECON.patch.md"
echo "  - webcheck/findings-candidates.md"
echo "  - webcheck/raw/*.json"
# cleanup() runs on EXIT