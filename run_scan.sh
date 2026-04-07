#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-}"
SECRET="${2:-${NUCLEI_SECRET_FILE:-}}"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target> [nuclei-secret.yaml]"
    echo "Example: $0 https://example.com"
    echo "Authenticated Nuclei scan: $0 https://example.com ./nuclei-secret.generated.yaml"
    echo "Or set NUCLEI_SECRET_FILE instead of the second argument."
    echo "Parallel worker processes: VAPT_PARALLEL=1 $0 ..."
    exit 1
fi

docker build -t argus-scan .

REPORTS_VOL="$(pwd)/reports"
DOCKER_ARGS=(--rm -v "$REPORTS_VOL:/app/reports")
EXTRA_ARGS=(--target "$TARGET" --full)
if [ "${VAPT_PARALLEL:-0}" = "1" ]; then
    EXTRA_ARGS+=(--parallel)
fi

if [ -n "$SECRET" ]; then
    SECRET_ABS="$(cd "$(dirname "$SECRET")" && pwd)/$(basename "$SECRET")"
    DOCKER_ARGS+=(-v "$SECRET_ABS:/app/nuclei-secret.yaml:ro")
    EXTRA_ARGS+=(--nuclei-secret-file /app/nuclei-secret.yaml)
    EXTRA_ARGS+=(--verbose)
fi

docker run "${DOCKER_ARGS[@]}" argus-scan:latest "${EXTRA_ARGS[@]}"

# Match reporter.py safe_target: strip scheme, then replace / and : with _
SAFE_SLUG="${TARGET#https://}"
SAFE_SLUG="${SAFE_SLUG#http://}"
SAFE_SLUG="${SAFE_SLUG//\//_}"
SAFE_SLUG="${SAFE_SLUG//:/_}"
report_file="$(ls -t reports/vapt_report_"${SAFE_SLUG}"_*.html 2>/dev/null | head -1 || true)"

if [ -z "$report_file" ]; then
    echo "Report file not found under reports/ for this target."
    exit 1
fi

open "$report_file"
