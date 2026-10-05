#!/usr/bin/env bash
# cryptoh demo — runs the whole pipeline in one shot.
#
#   Step 1  negative control   benign traffic must NOT alert
#   Step 2  detection          the attack window fires the 2-of-3 rule
#   Step 3  diagnosis          the model explains it and writes a mitigation
#   Step 4  live dashboard     tails a real file, pushes SSE to the browser
#
# Usage:
#   ./scripts/demo.sh                 # everything (dashboard on :8000)
#   ./scripts/demo.sh --no-ui         # terminal only, no server
#   ./scripts/demo.sh --no-model      # skip the model call (offline heuristic)
#   ./scripts/demo.sh --port 8011     # dashboard on another port
#   ./scripts/demo.sh --hold 0        # exit as soon as the dashboard is up
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$PWD"

PORT=8000
WITH_UI=1
WITH_MODEL=1
HOLD=1          # 1 = keep the dashboard up until Ctrl-C
LIVE_LOG="${TMPDIR:-/tmp}/cryptoh-live-demo.log"
OUT_DIR="${TMPDIR:-/tmp}/cryptoh-demo"
SERVER_PID=""

while [ $# -gt 0 ]; do
  case "$1" in
    --no-ui)    WITH_UI=0 ;;
    --no-model) WITH_MODEL=0 ;;
    --port)     PORT="$2"; shift ;;
    --hold)     HOLD="$2"; shift ;;
    -h|--help)  sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done

cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

step() { printf '\n\033[1;36m%s\033[0m\n%s\n' "$1" "$(printf '%.0s-' {1..72})"; }

command -v uv >/dev/null 2>&1 || { echo "uv not found — install it from https://docs.astral.sh/uv/" >&2; exit 1; }

# Load the model key if one is configured (.env is gitignored and never committed).
set -a
# shellcheck disable=SC1091
[ -f .env ] && . ./.env
set +a

if [ "$WITH_MODEL" -eq 1 ] && [ -z "${GEMINI_API_KEY:-}" ]; then
  echo "note: GEMINI_API_KEY not set — step 3 will use the built-in offline heuristic."
  echo "      set it in .env to get the real model diagnosis."
fi

step "STEP 1/4 — negative control: benign traffic must stay quiet"
uv run python -m cryptoh batch --source data/nginx_normal.log --no-mitigate

step "STEP 2/4 — detection: the C2 beacon mesh must trip the 2-of-3 rule"
uv run python -m cryptoh batch --source data/nginx_c2_attack.log --no-mitigate --output-dir "$OUT_DIR"
echo
echo "anomaly topology images:"
ls -1 "$OUT_DIR"/*.png 2>/dev/null | sed 's/^/  /' || echo "  (none)"

step "STEP 3/4 — diagnosis: model reads the topology and proposes a fix"
if [ "$WITH_MODEL" -eq 1 ]; then
  # 'n' declines the apply prompt automatically; the script is still shown.
  printf 'n\n' | uv run python -m cryptoh batch --source data/nginx_c2_attack.log --output-dir "$OUT_DIR" || \
    echo "model call failed — falling back is automatic; see cryptoh-audit/"
else
  echo "skipped (--no-model)"
fi

if [ "$WITH_UI" -eq 0 ]; then
  step "done (terminal only). artefacts: $OUT_DIR  |  cryptoh-audit/  |  cryptoh-report/"
  exit 0
fi

step "STEP 4/4 — live dashboard: real file ingestion streamed to the browser"
head -n 2600 data/nginx_normal.log > "$LIVE_LOG"
echo "seeding $(wc -l < "$LIVE_LOG") benign lines into $LIVE_LOG"

CRYPTOH_SOURCE="$LIVE_LOG" uv run uvicorn cryptoh.web.server:app --host 127.0.0.1 --port "$PORT" &
SERVER_PID=$!

for _ in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:$PORT/api/v1/health" >/dev/null 2>&1; then break; fi
  sleep 0.5
done

if ! curl -fsS "http://127.0.0.1:$PORT/api/v1/health" >/dev/null 2>&1; then
  echo "dashboard failed to start — see the log above" >&2
  exit 1
fi

echo "health: $(curl -fsS "http://127.0.0.1:$PORT/api/v1/health")"
echo
echo "  >>> open  http://127.0.0.1:$PORT/"

# Inject the attack tail shortly after startup so the dashboard fires on its own.
(
  sleep 6
  tail -n 600 data/nginx_c2_attack.log >> "$LIVE_LOG"
  echo
  echo "injected 600 attack lines — watch the feed, topology and mitigation panel."
) &

if [ "$HOLD" -eq 1 ]; then
  echo
  echo "Ctrl-C stops the demo and the server."
  wait "$SERVER_PID"
else
  sleep 20
  step "done. artefacts: $OUT_DIR  |  cryptoh-audit/  |  cryptoh-report/"
fi
