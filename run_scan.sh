#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-}"
SECRET="${2:-${NUCLEI_SECRET_FILE:-}}"
# Optional: path to site manifest YAML (mounted at /app/site-manifest.yaml)
SITE_MANIFEST="${SITE_MANIFEST:-}"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target> [nuclei-secret.yaml]"
    echo "Example: $0 https://example.com"
    echo "Authenticated Nuclei scan: $0 https://example.com ./nuclei-secret.generated.yaml"
    echo "Or set NUCLEI_SECRET_FILE instead of the second argument."
    echo "Parallel worker processes: VAPT_PARALLEL=1 $0 ..."
    echo "Nikto force CGI dir checks: NIKTO_CGI_ALL=1 $0 ... (slower)"
    echo "CI: fail if any stage incomplete: STRICT_EXIT=1 $0 ..."
    echo "Site manifest: SITE_MANIFEST=./my-site.yaml $0 https://example.com"
    echo "ZAP JSON/HTML in reports/ (from scripts/run_zap_baseline.sh): set RUN_ZAP=1 or pass files manually via --zap-report-json (see README)."
    exit 1
fi

docker build -t argus-scan .

REPORTS_VOL="$(pwd)/reports"
mkdir -p "$REPORTS_VOL"
DOCKER_ARGS=(--rm -v "$REPORTS_VOL:/app/reports")
EXTRA_ARGS=(--target "$TARGET" --full)
if [ "${VAPT_PARALLEL:-0}" = "1" ]; then
    EXTRA_ARGS+=(--parallel)
fi
if [ "${NIKTO_CGI_ALL:-0}" = "1" ]; then
    EXTRA_ARGS+=(--nikto-cgi-all)
fi
if [ "${STRICT_EXIT:-0}" = "1" ]; then
    EXTRA_ARGS+=(--strict-exit)
fi

if [ -n "$SECRET" ]; then
    SECRET_ABS="$(cd "$(dirname "$SECRET")" && pwd)/$(basename "$SECRET")"
    DOCKER_ARGS+=(-v "$SECRET_ABS:/app/nuclei-secret.yaml:ro")
    EXTRA_ARGS+=(--nuclei-secret-file /app/nuclei-secret.yaml)
    EXTRA_ARGS+=(--verbose)
fi

if [ -n "$SITE_MANIFEST" ]; then
    MAN_ABS="$(cd "$(dirname "$SITE_MANIFEST")" && pwd)/$(basename "$SITE_MANIFEST")"
    if [ -d "$MAN_ABS" ]; then
        echo "SITE_MANIFEST must be a YAML file, not a directory: $MAN_ABS" >&2
        exit 1
    fi
    if [ ! -f "$MAN_ABS" ]; then
        echo "SITE_MANIFEST must exist on the host before Docker runs: $MAN_ABS" >&2
        echo "If the path is missing, Docker creates a directory at the mount point and the container will fail." >&2
        exit 1
    fi
    DOCKER_ARGS+=(-v "$MAN_ABS:/app/site-manifest.yaml:ro")
    EXTRA_ARGS+=(--site-manifest /app/site-manifest.yaml)
fi

# Optional: run ZAP baseline first (requires Docker; official image - not deprecated owasp/zap2docker-stable)
ZAP_DOCKER_IMAGE="${ZAP_DOCKER_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
if [ "${RUN_ZAP:-0}" = "1" ]; then
    echo "Running ZAP baseline ($ZAP_DOCKER_IMAGE) -> $REPORTS_VOL (zap-report.json, zap-report.html)"
    docker run --rm -v "$REPORTS_VOL:/zap/wrk/:rw" "$ZAP_DOCKER_IMAGE" \
        zap-baseline.py -t "$TARGET" -J zap-report.json -r zap-report.html
    EXTRA_ARGS+=(--zap-report-json /app/reports/zap-report.json)
    EXTRA_ARGS+=(--zap-report-html /app/reports/zap-report.html)
fi

# If ZAP was run earlier, allow linking without re-running
if [ -f "$REPORTS_VOL/zap-report.json" ] && [[ "${EXTRA_ARGS[*]}" != *"--zap-report-json"* ]]; then
    EXTRA_ARGS+=(--zap-report-json /app/reports/zap-report.json)
    [ -f "$REPORTS_VOL/zap-report.html" ] && EXTRA_ARGS+=(--zap-report-html /app/reports/zap-report.html)
fi

docker run "${DOCKER_ARGS[@]}" argus-scan:latest "${EXTRA_ARGS[@]}"

# Match reporter.py safe_target: strip scheme, then replace / and : with _
SAFE_SLUG="${TARGET#https://}"
SAFE_SLUG="${SAFE_SLUG#http://}"
SAFE_SLUG="${SAFE_SLUG//\//_}"
SAFE_SLUG="${SAFE_SLUG//:/_}"
# Newest HTML report: nested reports/<site>/<timestamp>/ or legacy flat reports/
report_file=""
if command -v find >/dev/null 2>&1; then
    report_file="$(find reports -type f -name "vapt_report_${SAFE_SLUG}_*.html" -print0 2>/dev/null | xargs -0 ls -t 2>/dev/null | head -n 1 || true)"
fi
if [ -z "$report_file" ]; then
    report_file="$(ls -t reports/vapt_report_"${SAFE_SLUG}"_*.html 2>/dev/null | head -n 1 || true)"
fi

if [ -z "$report_file" ] || [ ! -f "$report_file" ]; then
    echo "Report file not found under reports/ for this target. Expected name pattern: vapt_report_${SAFE_SLUG}_*.html"
    exit 1
fi

open "$report_file"
