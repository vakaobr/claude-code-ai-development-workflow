#!/usr/bin/env bash
# Lifecycle manager for the on-demand, self-hosted web-check instance.
#
#   webcheck-up.sh up      # docker compose up -d, wait for /api/status healthy
#   webcheck-up.sh down    # docker compose down (stop + remove container)
#   webcheck-up.sh status  # is the API responding?
#   webcheck-up.sh logs    # tail container logs (debugging)
#
# The container is bound to 127.0.0.1:3000 by docker-compose.yml. This
# script never exposes it more widely.
set -euo pipefail

PROJECT="web-check-recon"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # skill dir (has compose file)
COMPOSE_FILE="$HERE/docker-compose.yml"
API="http://127.0.0.1:3000/api/status?url=https://example.com"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-90}"   # seconds to wait for first-boot + image pull

compose() {
  # Prefer `docker compose` (v2); fall back to `docker-compose` (v1).
  if docker compose version >/dev/null 2>&1; then
    docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"
  else
    echo "ERROR: neither 'docker compose' nor 'docker-compose' is available" >&2
    exit 127
  fi
}

api_up() { curl -fsS --max-time 8 "$API" >/dev/null 2>&1; }

cmd_up() {
  if api_up; then
    echo "web-check already healthy at 127.0.0.1:3000"
    return 0
  fi
  echo "Starting web-check (project: $PROJECT)..."
  echo "Note: first run pulls lissy93/web-check (~1 GB, bundles Chromium)."
  compose up -d

  echo -n "Waiting for /api/status to respond (timeout ${HEALTH_TIMEOUT}s)"
  local waited=0
  while (( waited < HEALTH_TIMEOUT )); do
    if api_up; then
      echo ""
      echo "web-check is healthy at http://127.0.0.1:3000 (API only)."
      return 0
    fi
    sleep 3; waited=$((waited+3)); echo -n "."
  done

  echo ""
  echo "ERROR: web-check did not become healthy within ${HEALTH_TIMEOUT}s." >&2
  echo "----- last 40 log lines -----" >&2
  compose logs --tail 40 >&2 || true
  exit 1
}

cmd_pull()   { echo "Pulling lissy93/web-check (~1 GB, one-time)..."; compose pull; echo "Pull complete."; }
cmd_down()   { echo "Stopping web-check..."; compose down; echo "Done."; }
cmd_status() { if api_up; then echo "UP   (http://127.0.0.1:3000)"; else echo "DOWN"; exit 1; fi; }
cmd_logs()   { compose logs --tail "${1:-100}" -f; }

case "${1:-}" in
  pull)   cmd_pull ;;
  up)     cmd_up ;;
  down)   cmd_down ;;
  status) cmd_status ;;
  logs)   shift; cmd_logs "${1:-100}" ;;
  *) echo "usage: $0 {pull|up|down|status|logs}" >&2; exit 2 ;;
esac
