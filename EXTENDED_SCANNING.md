# Extended scanning: manifests, ZAP, and other tools

This document complements the main [README](README.md). It describes operational practices and optional tools that work alongside Argus-Scan.

## Security score semantics

The HTML/Markdown dossier **security score** aggregates severity-weighted findings from:

- Python checks: HTTP security headers, SSL certificate issues, and high-risk open ports (Nmap).
- **Nuclei**: parsed from the JSONL export (`-jle`), not from raw stdout alone.
- **ZAP** (optional): parsed from a traditional JSON report produced by `zap-baseline.py` (`-J`).

**Nikto** output is included in **Raw Module Data** but is **not** parsed into scored findings (same as before for Nikto).

Use the executive summary as a **signal**, not a substitute for manual review or a full penetration test.

## Site manifest (`--site-manifest`)

Maintain a YAML file listing important routes (login, password reset, search, forms, authenticated areas). Argus expands it to absolute URLs, writes a plain list file, and runs Nuclei with `-list`.

See [examples/site-manifest.example.yaml](examples/site-manifest.example.yaml).

- By default, Argus **prepends** `--target` to the list if it is missing (`--no-site-manifest-include-primary` to disable).
- **Authentication**: use `--nuclei-secret-file` so Nuclei sends cookies on requests to protected URLs.
- Manifest entries **do not** automatically fuzz specific parameters for SQL injection; use ZAP/Burp or scoped tooling for targeted injection tests.

## OWASP ZAP baseline

ZAP is **not** bundled inside the Argus Docker image (size and process model). Run it as a separate step and pass reports into Argus. Helper scripts default to **`ghcr.io/zaproxy/zaproxy:stable`** ([ZAP Docker guide](https://www.zaproxy.org/docs/docker/about/)); the legacy **`owasp/zap2docker-stable`** image is deprecated. Set **`ZAP_DOCKER_IMAGE`** to override (for example `zaproxy/zap-stable`).

```bash
./scripts/run_zap_baseline.sh https://your-app.example.com ./reports
docker run --rm -v "$(pwd)/reports:/app/reports" argus-scan:latest \
  --target https://your-app.example.com --full \
  --zap-report-json /app/reports/zap-report.json \
  --zap-report-html /app/reports/zap-report.html
```

Tune ZAP policies, authentication, and rate limits for **production** targets; prefer **staging** when possible.

## Other open-source tools (manual / pipeline)

| Tool | Use |
|------|-----|
| **Katana** | Crawl to build a URL list → feed Nuclei `-list` or grow your manifest. |
| **httpx** | Probe URLs from a list (status, tech fingerprint) before heavy scans. |
| **Dalfox** | Focused XSS testing on selected URLs/parameters (scope carefully). |
| **Wapiti** | Alternative DAST; overlaps with ZAP—usually pick one primary scanner. |
| **testssl.sh** / **sslscan** | Deeper TLS review than Argus’s Python SSL check. |
| **ffuf / feroxbuster** | Directory and parameter fuzzing—**high risk** on production; use staging. |
| **sqlmap** | SQL injection testing—**can be destructive**; only with explicit approval, scoped parameters, and non-production or dedicated sandboxes. |

## Operational best practices

- Obtain **written authorization** and define **scope** (hosts, paths, rate limits, forbidden actions).
- Run aggressive or state-changing tests on **staging** first; schedule **off-hours** windows for production smoke scans.
- **Rate-limit** crawlers and active scanners; monitor for lockouts and fraud triggers.
- Treat **sqlmap**, heavy fuzzing, and destructive checks as **out of band** unless explicitly approved—they are not part of Argus defaults.
