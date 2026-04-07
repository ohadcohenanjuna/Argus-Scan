#!/usr/bin/env bash
# Open an isolated Chrome profile against a URL, let you log in, then export
# cookies via DevTools and write a Nuclei Secret File for authenticated scans.
# See: https://docs.projectdiscovery.io/opensource/nuclei/authenticated-scans
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

usage() {
  echo "Usage: $0 <start-url> [output-secret.yaml]"
  echo ""
  echo "Environment:"
  echo "  SCAN_TARGET       Start URL when the first argument is omitted (handy with run_scan.sh workflows)"
  echo "  CHROME            Path to Chrome/Chromium (default: auto)"
  echo "  CHROME_USER_DATA  Profile directory (default: $SCRIPT_DIR/.chrome-argus-auth-profile)"
  echo "  CHROME_DEBUG_PORT        Port for remote debugging (default: random free port)"
  echo "  CHROME_REMOTE_ALLOW_ORIGINS  DevTools WebSocket allowlist (default: *). Required on Chrome 111+."
  echo "  AUTH_SCAN_SKIP_VALIDATE  Set to 1 to skip the post-capture HTTP cookie check"
  echo "  AUTH_SCAN_VALIDATE_URL   Optional URL for validation only (e.g. a protected API path);"
  echo "                           default is the same as <start-url>. CDP capture still uses <start-url>."
  exit 1
}

START_URL="${1:-${SCAN_TARGET:-}}"
OUT_FILE="${2:-$SCRIPT_DIR/nuclei-secret.generated.yaml}"

if [[ -z "$START_URL" ]]; then
  echo "Error: no start URL. Pass it as the first argument, or export SCAN_TARGET=https://..." >&2
  echo "Example: $0 https://docs.example.com/" >&2
  usage
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
  CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
else
  CHROME="${CHROME:-google-chrome}"
  if ! command -v "$CHROME" &>/dev/null; then
    CHROME="chromium"
  fi
  if ! command -v "$CHROME" &>/dev/null; then
    CHROME="google-chrome-stable"
  fi
fi

if [[ ! -x "$CHROME" ]] && ! command -v "$CHROME" &>/dev/null; then
  echo "Chrome/Chromium not found. Set CHROME to the browser binary path." >&2
  exit 1
fi

USER_DATA_DIR="${CHROME_USER_DATA:-$SCRIPT_DIR/.chrome-argus-auth-profile}"
mkdir -p "$USER_DATA_DIR"

if [[ -n "${CHROME_DEBUG_PORT:-}" ]]; then
  PORT="$CHROME_DEBUG_PORT"
else
  PORT="$(python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()")"
fi

PYTHON="${SCRIPT_DIR}/venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON="python3"
fi

if ! "$PYTHON" -c "import websocket, yaml" 2>/dev/null; then
  echo "Missing Python deps (websocket-client, pyyaml). From this directory run:" >&2
  echo "  python3 -m venv venv && ./venv/bin/pip install -r requirements.txt" >&2
  exit 1
fi

echo "Starting isolated Chrome (profile: $USER_DATA_DIR)"
echo "DevTools port: $PORT"
echo "Opening: $START_URL"
echo ""
echo "1. Sign in to the app in the Chrome window."
echo "2. When finished, return here and press Enter to capture cookies for Nuclei."
echo "   (After capture, the script GETs a URL with those cookies to sanity-check the session."
echo "    For SPAs, set AUTH_SCAN_VALIDATE_URL to a path that requires auth, e.g. an API /me endpoint.)"
echo ""

# Chrome 111+ rejects CDP WebSocket handshakes unless the Origin is allowlisted.
REMOTE_ORIGINS="${CHROME_REMOTE_ALLOW_ORIGINS:-*}"

"$CHROME" \
  --user-data-dir="$USER_DATA_DIR" \
  --remote-debugging-port="$PORT" \
  --remote-allow-origins="$REMOTE_ORIGINS" \
  --no-first-run \
  --no-default-browser-check \
  --disable-popup-blocking \
  "$START_URL" &
CHROME_PID=$!

cleanup() {
  if kill -0 "$CHROME_PID" 2>/dev/null; then
    kill "$CHROME_PID" 2>/dev/null || true
    wait "$CHROME_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

read -r _

CAPTURE_ARGS=(--port "$PORT" --url "$START_URL" -o "$OUT_FILE")
if [[ -n "${AUTH_SCAN_VALIDATE_URL:-}" ]]; then
  CAPTURE_ARGS+=(--validate-url "$AUTH_SCAN_VALIDATE_URL")
fi
if [[ "${AUTH_SCAN_SKIP_VALIDATE:-}" == "1" ]]; then
  CAPTURE_ARGS+=(--no-validate)
fi
"$PYTHON" "$SCRIPT_DIR/capture_cookies_cdp.py" "${CAPTURE_ARGS[@]}"

echo ""
echo "Secret file: $OUT_FILE"
echo "Run the scan (rebuilds image and mounts the secret file):"
echo "  ./run_scan.sh \"$START_URL\" \"$OUT_FILE\""
