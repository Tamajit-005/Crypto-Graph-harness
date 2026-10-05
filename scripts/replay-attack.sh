#!/usr/bin/env bash
# Demo replay: stream the benign log, then the attack log in chunks.
# Usage: ./scripts/replay-attack.sh [target-file]
set -euo pipefail
TARGET="${1:-/tmp/cryptoh-replay.log}"
: > "$TARGET"
echo "replaying benign traffic -> $TARGET"
head -n 1300 data/nginx_normal.log >> "$TARGET"
sleep 1
tail -n +1301 data/nginx_normal.log >> "$TARGET"
sleep 1
echo "replaying attack traffic -> $TARGET"
split -n l/5 -d data/nginx_c2_attack.log /tmp/cryptoh-chunk-
for c in /tmp/cryptoh-chunk-*; do
  cat "$c" >> "$TARGET"
  sleep 1
done
rm -f /tmp/cryptoh-chunk-*
echo "replay done: $(wc -l < "$TARGET") lines in $TARGET"
