#!/usr/bin/env bash
# Calls the local web-check API for each check in the selected tier and
# saves one JSON file per check.
#
#   run-webcheck.sh <target> <tier> <out_dir>
#     target   in-scope hostname (no scheme), e.g. app.example.com
#     tier     passive | active     (active = passive set + active set)
#     out_dir  directory to write {check}.json into
#
#   Env:
#     INCLUDE_TLS_LABS=1   also run the public Qualys SSL Labs scan
#                          (OFF by default - see SKILL.md authorization step 4)
#     RATE_LIMIT_RPS=N     spacing between requests (default 4)
#     API_BASE=...         override (default http://127.0.0.1:3000/api)
#
# Active probing is gated by the CALLER (the skill checks the scope file
# before passing tier=active). This script only honors the tier it's given.
set -uo pipefail

TARGET="${1:?usage: run-webcheck.sh <target> <tier> <out_dir>}"
TIER="${2:?tier must be 'passive' or 'active'}"
OUT_DIR="${3:?out_dir required}"
API_BASE="${API_BASE:-http://127.0.0.1:3000/api}"
RATE_LIMIT_RPS="${RATE_LIMIT_RPS:-4}"

# Reject schemes / paths in the target - we only accept a bare host.
if [[ "$TARGET" == *"://"* || "$TARGET" == *"/"* ]]; then
  echo "ERROR: pass a bare hostname (no scheme, no path): got '$TARGET'" >&2
  exit 2
fi

# Third-party OSINT lookups + at most one benign GET / TLS handshake each.
PASSIVE_CHECKS=(
  archives block-lists carbon cookies dns dns-server dnssec get-ip
  headers hsts http-security location mail-config rank redirects
  robots-txt security-txt shodan sitemap social-tags ssl status
  subdomains tech-stack threats tls-connection txt-records whois
)

# Send real probes / load to the target - require testing_level: active.
ACTIVE_CHECKS=( ports trace-route firewall linked-pages quality screenshot )

case "$TIER" in
  passive) CHECKS=( "${PASSIVE_CHECKS[@]}" ) ;;
  active)  CHECKS=( "${PASSIVE_CHECKS[@]}" "${ACTIVE_CHECKS[@]}" ) ;;
  *) echo "ERROR: tier must be 'passive' or 'active', got '$TIER'" >&2; exit 2 ;;
esac

# Opt-in: public Qualys SSL Labs scan.
if [[ "${INCLUDE_TLS_LABS:-0}" == "1" ]]; then
  CHECKS+=( tls-labs )
fi

mkdir -p "$OUT_DIR"
URL="https://${TARGET}"
SLEEP=$(awk "BEGIN{ r=$RATE_LIMIT_RPS; if (r<=0) r=1; printf \"%.3f\", 1.0/r }")

echo "web-check-recon: target=$TARGET tier=$TIER checks=${#CHECKS[@]} rps=$RATE_LIMIT_RPS"
echo "output -> $OUT_DIR"

ok=0; err=0
for check in "${CHECKS[@]}"; do
  out="$OUT_DIR/${check}.json"
  code=$(curl -sS -G "$API_BASE/${check}" \
              --data-urlencode "url=${URL}" \
              --max-time 60 \
              -o "$out" -w '%{http_code}' 2>"$OUT_DIR/${check}.curlerr" || echo "000")
  if [[ "$code" == "200" ]]; then
    printf '  [ok ] %-14s\n' "$check"; ok=$((ok+1)); rm -f "$OUT_DIR/${check}.curlerr"
  else
    printf '  [err] %-14s (http %s)\n' "$check" "$code"
    mv -f "$out" "$OUT_DIR/${check}.error.txt" 2>/dev/null || true
    echo "http=$code" >> "$OUT_DIR/${check}.error.txt"
    err=$((err+1))
  fi
  sleep "$SLEEP"
done

echo "done: $ok ok, $err errored (errors saved as {check}.error.txt)"
