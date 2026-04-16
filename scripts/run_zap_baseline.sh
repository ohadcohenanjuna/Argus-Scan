#!/usr/bin/env bash
# Run ZAP baseline against a URL and write traditional JSON + HTML into a reports directory.
# Feed the JSON into Argus with: --zap-report-json /app/reports/zap-report.json
#
# Requires: Docker
# Reference: https://www.zaproxy.org/docs/docker/baseline/
#
# Official image (do not use deprecated owasp/zap2docker-stable):
#   https://www.zaproxy.org/docs/docker/about/
set -euo pipefail

# Override if needed: ZAP_DOCKER_IMAGE=zaproxy/zap-stable ./scripts/run_zap_baseline.sh ...
ZAP_DOCKER_IMAGE="${ZAP_DOCKER_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"

TARGET="${1:-}"
OUT_DIR="${2:-./reports}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <target-url> [reports-dir]"
  echo "Example: $0 https://example.com ./reports"
  exit 1
fi

mkdir -p "$OUT_DIR"
OUT_ABS="$(cd "$(dirname "$OUT_DIR")" && pwd)/$(basename "$OUT_DIR")"

echo "Running ZAP baseline ($ZAP_DOCKER_IMAGE) → $OUT_ABS (zap-report.json, zap-report.html)"
docker run --rm \
  -v "$OUT_ABS:/zap/wrk/:rw" \
  "$ZAP_DOCKER_IMAGE" \
  zap-baseline.py \
  -t "$TARGET" \
  -J zap-report.json \
  -r zap-report.html

echo "Done. Pass to Argus: --zap-report-json $OUT_ABS/zap-report.json --zap-report-html $OUT_ABS/zap-report.html"
