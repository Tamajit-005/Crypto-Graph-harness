#!/usr/bin/env bash
set -euo pipefail
LOGFILE="${1:-data/nginx_c2_attack.log}"
DELAY="${2:-0.1}"
if [ ! -f "$LOGFILE" ]; then
  echo "log file not found: $LOGFILE" >&2
  exit 1
fi
tail -F "$LOGFILE" | while IFS= read -r line; do
  echo "$line"
  sleep "$DELAY"
done
