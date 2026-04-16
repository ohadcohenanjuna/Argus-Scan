# Argus-Scan: Automated Vulnerability Assessment Tool

Argus-Scan is an open-source vulnerability assessment tool for web applications and internal services. It combines **Nmap**, **Nikto**, and **Nuclei** with Python checks (HTTP security headers, TLS). Optional features include a **YAML site manifest** so Nuclei scans multiple curated URLs (`-list`), **Nuclei JSONL** parsing into scored findings, and ingestion of **OWASP ZAP** baseline JSON/HTML for DAST results in the same report. See [EXTENDED_SCANNING.md](EXTENDED_SCANNING.md) for score semantics, production safety, and complementary tools (Katana, httpx, and similar).

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11+-yellow.svg)
![Docker](https://img.shields.io/badge/docker-ready-blue.svg)

---

## Table of Contents

- [Features](#-features)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Quick start (manifest + scan)](quick-start.md)
- [Usage](#-usage)
  - [Using run_scan.sh](#using-run_scansh)
  - [Site manifest (curated URLs)](#site-manifest-curated-urls)
  - [OWASP ZAP reports](#owasp-zap-reports)
  - [Authenticated scan](#authenticated-scan)
- [Reporting](#-reporting)
- [Extended scanning (manifest, ZAP, other tools)](EXTENDED_SCANNING.md)
- [CI/CD Integration](#-cicd-integration)
- [How It Works](#-how-it-works)
- [Troubleshooting](#-troubleshooting)
- [Future Roadmap](#-future-roadmap)
- [Disclaimer](#-disclaimer)

---

## 🚀 Features

| Feature | Description |
|--------|-------------|
| **Port Scanning** | Identifies open ports and running services using Nmap. Flags risky services (FTP, Telnet, RDP, SMB, MySQL). |
| **Security Headers** | Checks for missing or misconfigured HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy). TLS verification is **on by default**; use `--insecure` only for lab or self-signed targets. |
| **SSL/TLS Inspection** | Validates certificate expiry and connection to port 443. |
| **Vulnerability Scanning** | With `--full`, runs Nikto (web vulnerability scanner) and Nuclei (template-based scanning). |
| **Dashboard Reporting** | Generates an elegant "Intelligence Dossier" HTML report (with dark/light mode toggle), and a detailed Markdown report with severity counts and recommendations. Reports state whether **Nuclei** ran with a secret file (`--nuclei-secret-file`); port, header, SSL, and Nikto stages are always unauthenticated. |
| **Nuclei JSONL findings** | Nuclei exports JSONL (`-jle`); Argus parses severities into the scored findings list (not only raw text). |
| **Site manifest** | Optional YAML (`--site-manifest`) lists curated URLs; Nuclei runs with `-list` for broader coverage (see `examples/site-manifest.example.yaml`). |
| **ZAP reports** | Optional `--zap-report-json` / `--zap-report-html` ingest OWASP ZAP baseline output; see [EXTENDED_SCANNING.md](EXTENDED_SCANNING.md). |
| **Cookie export validation** | After CDP capture, optional HTTP checks validate the session before you run Nuclei: anonymous GET first, then GET with cookies, using an opener **without** a cookie jar. Compares **final URLs** after redirects (not only status codes) so redirect-to-login and SSO flows are recognized when anonymous users would see `/login` or an IdP while 200 responses look identical. |
| **CI/CD Ready** | GitLab CI configuration for building the image and running scans with reports as artifacts. |

---

## 📂 Project Structure

```text
.
├── src/
│   ├── vapt.py             # Main entrypoint and CLI
│   ├── scanners.py         # Scanner modules (Port, Header, SSL, Tool)
│   ├── reporter.py         # Reporting logic (CLI, HTML, Markdown)
│   ├── nuclei_runner.py    # Nuclei subprocess + JSONL export (`-jle`)
│   ├── nuclei_parse.py     # Parse Nuclei JSONL into scored findings
│   ├── site_manifest.py    # YAML manifest → URL list for Nuclei `-list`
│   ├── zap_parse.py        # Parse ZAP traditional JSON into findings
│   ├── parallel_workers.py # Multiprocessing helpers for `--parallel`
│   ├── parallel_ui.py      # Rich live table for parallel job status
│   └── templates/          # Jinja2 HTML report template
├── tests/                  # Unit tests (e.g. parsers); run in Docker: see below
├── reports/                # Generated reports (created if missing)
├── setup.sh                # Setup script for Linux/WSL
├── requirements.txt        # Python dependencies
├── auth_scan_chrome.sh     # Chrome + CDP: log in, export cookies to a Nuclei Secret File
├── capture_cookies_cdp.py  # Helper used by auth_scan_chrome.sh
├── examples/               # Example site manifest for Nuclei -list
├── scripts/run_zap_baseline.sh  # Optional: ZAP baseline → reports dir
├── EXTENDED_SCANNING.md    # Manifests, ZAP, score semantics, other OSS tools
├── run_scan.sh             # Build image and run scan (optional Nuclei secret mount)
├── Dockerfile              # Container image definition
├── .dockerignore           # Build context exclusions
└── .gitlab-ci.yml          # GitLab CI pipeline
```

**Run and import expectations**

- **Native run:** Execute from the **repository root** so that `python src/vapt.py` resolves imports correctly (the directory of the script is on `sys.path`).
- **Docker:** The image sets `PYTHONPATH=/app/src` and runs `python src/vapt.py` from `/app`. No extra setup is required.

---

## 🛠️ Installation

### Method 1: Docker (Recommended)

Docker bundles Nmap, Nikto, Nuclei, and Python dependencies. No host install needed.

**Build the image** (tag matches `run_scan.sh`; use any name you prefer):

```bash
docker build -t argus-scan .
```

**Run a scan:**

```bash
docker run --rm -v "$(pwd)/reports:/app/reports" argus-scan:latest --target https://example.com
```

The image entrypoint is `python src/vapt.py`. On some setups you may omit `:latest`.

### Method 2: Manual Installation (Linux / WSL)

**Prerequisites:** Python 3.8+ (3.11+ recommended), sudo access for system tools.

1. **Run the setup script:**

   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

   This creates a virtual environment (`venv`) and checks for Nmap, Nikto, and Nuclei. Missing tools are reported; the script does not install them on all systems.

2. **Activate the environment and run:**

   ```bash
   source venv/bin/activate
   python src/vapt.py --target example.com
   ```

   Always run `python src/vapt.py` from the **project root** (the directory that contains `src/` and `requirements.txt`).

**Windows**

- Use **Docker** or **WSL** and follow the Linux instructions. The native setup script is intended for Unix-like environments.

---

## 💻 Usage

### Basic scan

Runs port scan, security headers, and SSL checks. Does **not** run Nikto or Nuclei.

**Docker:**

```bash
docker run --rm -v "$(pwd)/reports:/app/reports" argus-scan:latest --target https://example.com
```

**Native (from repo root):**

```bash
python src/vapt.py --target example.com
```

### Full scan

Adds Nikto and Nuclei. Takes longer and requires those tools to be installed (or use Docker).

The **Docker image** runs `nuclei -update-templates` during the build, so Nuclei’s community templates live under `/root/nuclei-templates` in the image and a full scan does not spend its first run downloading them (the image is larger accordingly). On a **native** install, run `nuclei -update-templates` once after installing the binary if you see an install message in `logs/nuclei.log`. For a **custom or air-gapped** template tree, mount it over that path (for example `-v /path/on/host/nuclei-templates:/root/nuclei-templates:ro`).

**Docker:**

```bash
docker run --rm -v "$(pwd)/reports:/app/reports" argus-scan:latest --target https://example.com --full
```

**Native:**

```bash
python src/vapt.py --target example.com --full
```

### Using run_scan.sh

From the repo root, [`run_scan.sh`](run_scan.sh) builds the `argus-scan` image, runs a **full** scan, and opens the latest HTML report (macOS `open`).

| Input / env | Purpose |
|-------------|---------|
| `$1` | Target URL (required) |
| `$2` or `NUCLEI_SECRET_FILE` | Optional path to a Nuclei secret YAML (mounted as `/app/nuclei-secret.yaml`) |
| `VAPT_PARALLEL=1` | Run port/header/SSL and Nikto/Nuclei stages in parallel (more load on the target) |
| `NIKTO_CGI_ALL=1` | Nikto only: add `-C all` (force CGI checks everywhere; slower, use for legacy/CGI-heavy targets) |
| `LENIENT_EXIT=1` | Pass `--lenient-exit`: exit **0** even when a stage failed (default is exit **1** if any module did not complete) |
| `SITE_MANIFEST=./path.yaml` | Mount a [site manifest](#site-manifest-curated-urls) as `/app/site-manifest.yaml` |
| `RUN_ZAP=1` | Run **OWASP ZAP baseline** into `./reports/` first, then pass ZAP JSON/HTML into Argus |

If `reports/zap-report.json` already exists (for example from a previous [`scripts/run_zap_baseline.sh`](scripts/run_zap_baseline.sh) run), it is picked up automatically unless ZAP args were already added.

```bash
chmod +x run_scan.sh
./run_scan.sh https://example.com
VAPT_PARALLEL=1 SITE_MANIFEST=./my-site.yaml ./run_scan.sh https://example.com ./nuclei-secret.generated.yaml
RUN_ZAP=1 ./run_scan.sh https://example.com
```

### Site manifest (curated URLs)

For login, search, forms, and other routes Nuclei should hit beyond a single `--target`, maintain a YAML file and pass **`--site-manifest`** (requires **`--full`**). Argus expands paths, writes a plain-text URL list under `reports/`, and runs Nuclei with **`-list`**. By default the primary `--target` URL is prepended to that list; use **`--no-site-manifest-include-primary`** to disable.

Copy and edit [`examples/site-manifest.example.yaml`](examples/site-manifest.example.yaml). Combine with **`--nuclei-secret-file`** for authenticated pages.

**Docker example:**

```bash
docker run --rm \
  -v "$(pwd)/reports:/app/reports" \
  -v "$(pwd)/my-site.yaml:/app/site-manifest.yaml:ro" \
  argus-scan:latest \
  --target https://example.com --full \
  --site-manifest /app/site-manifest.yaml
```

### OWASP ZAP reports

ZAP is **not** installed inside the Argus image. Run [**ZAP baseline**](https://www.zaproxy.org/docs/docker/baseline/) in a separate container and point Argus at the generated reports so alerts are **parsed into the same score** (traditional JSON from `zap-baseline.py -J`).

The scripts use the current official image **`ghcr.io/zaproxy/zaproxy:stable`** (the old `owasp/zap2docker-stable` image is deprecated and no longer pullable). Override with **`ZAP_DOCKER_IMAGE`** if needed (for example `zaproxy/zap-stable` on Docker Hub).

```bash
./scripts/run_zap_baseline.sh https://example.com ./reports
docker run --rm -v "$(pwd)/reports:/app/reports" argus-scan:latest \
  --target https://example.com --full \
  --zap-report-json /app/reports/zap-report.json \
  --zap-report-html /app/reports/zap-report.html
```

Or use **`RUN_ZAP=1`** with [`run_scan.sh`](#using-run_scansh) so ZAP runs first and Argus consumes `./reports/zap-report.json`.

Details: [EXTENDED_SCANNING.md](EXTENDED_SCANNING.md).

### Authenticated scan

For targets that require a logged-in session, capture cookies from Chrome into a [Nuclei Secret File](https://docs.projectdiscovery.io/opensource/nuclei/authenticated-scans), then run a full Docker scan with that file mounted. `auth_scan_chrome.sh` uses an isolated Chrome profile and `capture_cookies_cdp.py`; `run_scan.sh` builds the image, mounts the secret, and runs `--full` with Nuclei authentication.

**Host prerequisites:** Docker, Chrome or Chromium, and Python 3 for the capture step.

**1. Python dependencies** (minimal set for the cookie capture scripts):

```bash
python3 -m venv venv && ./venv/bin/pip install pyyaml websocket-client
```

You can use `./venv/bin/pip install -r requirements.txt` instead; it includes these packages among others.

**2. Set the scan target** (URL you will open and sign in against):

```bash
export SCAN_TARGET="https://your-app.example.com"
```

**3. Log in and export cookies** (default output: `./nuclei-secret.generated.yaml`; optional **second argument** is the output path):

```bash
./auth_scan_chrome.sh "$SCAN_TARGET"
# Or pass the URL as the first argument; if you omit it, `SCAN_TARGET` is used instead.
```

**Secret file path:** Nuclei only needs a readable YAML path; the filename does not affect the scan. For a **single** target, `./nuclei-secret.generated.yaml` is fine. If you capture cookies for **more than one** host, use a **different file per target** so you do not overwrite another site’s cookies or mount the wrong session in `run_scan.sh`. A simple pattern (same slug rules as report filenames: strip `https://`, replace `/` and `:` with `_`):

```bash
SLUG="${SCAN_TARGET#https://}"; SLUG="${SLUG#http://}"; SLUG="${SLUG//\//_}"; SLUG="${SLUG//:/_}"
SECRET_FILE="./nuclei-secret.${SLUG}.yaml"
./auth_scan_chrome.sh "$SCAN_TARGET" "$SECRET_FILE"
```

After you press Enter, `capture_cookies_cdp.py` writes the Nuclei Secret File and (by default) runs a **validation step**: two HTTP GETs from Python (not Chrome)—first **without** a `Cookie` header, then **with** the captured cookies—using an opener that does **not** use a cookie jar, so the anonymous request cannot pick up cookies from the authenticated response.

- **`AUTH_SCAN_VALIDATE_URL`** — Optional. If set, this URL is used **only** for those validation GETs. Use it when the page you open for CDP (`SCAN_TARGET` / first argument) is public but you want to probe a **protected** path (for example `https://app.example.com/app/dashboard` or `https://docs.example.com/dev`) that redirects anonymous users to login or SSO. If unset, validation uses the same URL as the capture step.
- **`AUTH_SCAN_SKIP_VALIDATE=1`** — Skip the HTTP validation step after writing the YAML (for unusual TLS, air-gapped checks, etc.).
- **`capture_cookies_cdp.py`** supports the same behavior directly: `--validate-url <url>`, `--no-validate`.

Validation interprets **401/403**, and also **redirect chains**: many sites return **200** on a login page after redirects; the script compares **final URLs** (login/SSO path, off-site IdP host, `return_to=` query hints, etc.) so “both 200” does not always mean “no difference between anonymous and authenticated.”

**4. Run the scan** (rebuilds the image, mounts the secret, enables verbose output when a secret is present). Use `VAPT_PARALLEL=1` to run independent scan stages in parallel (higher load on the target). Pass the **same** YAML path you used in step 3:

```bash
VAPT_PARALLEL=1 ./run_scan.sh "$SCAN_TARGET" "./nuclei-secret.generated.yaml"
# If you set SECRET_FILE above:
# VAPT_PARALLEL=1 ./run_scan.sh "$SCAN_TARGET" "$SECRET_FILE"
```

Instead of the second argument, you can set `NUCLEI_SECRET_FILE` to the YAML path. For CLI-only use inside the container: `python src/vapt.py --target … --full --nuclei-secret-file /path/to/secret.yaml`.

### All options

| Flag | Short | Description |
|------|-------|-------------|
| `--target` | — | **Required.** URL or hostname to scan (e.g. `https://example.com`, `example.com`, `192.168.1.1`). |
| `--output` | — | Directory for report files (default: `reports`). |
| `--full` | — | Run Nikto and Nuclei in addition to port/header/SSL checks. |
| `--no-tool-check` | — | Skip checks for Nmap/Nikto/Nuclei. Use when you only want Python-based checks or in CI where tools are guaranteed. |
| `--verbose` | `-v` | Print tool commands and live tool output during scans. |
| `--insecure` | — | Disable TLS verification for the security-header HTTP request. Use only for lab or self-signed targets. |
| `--nuclei-secret-file` | — | Path to a Nuclei v3.2+ Secret File (YAML) for authenticated Nuclei scans; passed through as Nuclei’s `--secret-file`. |
| `--parallel` | — | Run independent scan stages in parallel worker processes (more load on the target). Tool stdout is written to **`logs/*.log`** under the session directory; the console shows a short job status table. **`--verbose` does not stream tools to the console in parallel mode** (use `tail -f` on the log files). |
| `--site-manifest` | — | YAML file of URLs/paths; Nuclei uses `-list` (see `examples/site-manifest.example.yaml`). |
| `--no-site-manifest-include-primary` | — | Do not prepend `--target` to the manifest URL list. |
| `--zap-report-json` | — | Path to ZAP traditional JSON (`zap-baseline.py -J`); findings are parsed into the dossier score. |
| `--zap-report-html` | — | Optional ZAP HTML path for cross-reference in the report (not parsed). |

**Examples:**

```bash
# Custom output directory
python src/vapt.py --target example.com --output ./my-reports

# Full scan with verbose tool output
python src/vapt.py --target example.com --full --verbose

# Skip dependency check (e.g. in Docker or CI)
docker run --rm -v "$(pwd)/reports:/app/reports" argus-scan:latest --target https://example.com --no-tool-check

# Full scan + site manifest + ZAP reports (after generating zap-report.json in reports/)
docker run --rm -v "$(pwd)/reports:/app/reports" \
  -v "$(pwd)/manifest.yaml:/app/site-manifest.yaml:ro" \
  argus-scan:latest --target https://example.com --full \
  --site-manifest /app/site-manifest.yaml \
  --zap-report-json /app/reports/zap-report.json \
  --zap-report-html /app/reports/zap-report.html

# Self-signed or internal HTTPS
python src/vapt.py --target https://internal.example.com --insecure
```

**Unit tests** (parsers; requires repo mounted):

```bash
docker run --rm -v "$(pwd):/app" -w /app --entrypoint python argus-scan:latest tests/test_argus_parsing.py -v
```

---

## 📊 Reporting

Reports are written under **`--output`/`<site-slug>`/`<scan-timestamp>`/** (default: `reports/<hostname>/<YYYYMMDD_HHMMSS>/`). The scan start time is fixed when the run begins. Parallel stages (**`--parallel`**) write live logs under **`logs/`** in that same folder (`port_scan.log`, `header_scan.log`, `ssl_scan.log`, `nikto.log`, `nuclei.log`) while the console shows a short status table instead of streaming tool output.

| Type | File pattern | Purpose |
|------|--------------|--------|
| **HTML** | `.../<site-slug>/<ts>/vapt_report_<target-slug>_<ts>.html` | "Intelligence Dossier" aesthetic dashboard with dark/light mode toggle. |
| **Markdown** | Same directory, `.md` | Technical summary and raw module output in collapsible sections. |

Both include:

- Security score (0–100) and grade (A–F)
- Severity counts (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Per-finding description, current state, and recommendation
- **Nuclei scan mode:** whether Nuclei ran **with** a `--nuclei-secret-file` (authenticated Nuclei) or **without**, or Nuclei was **not** run (no `--full`). Other scan stages (port, headers, SSL, Nikto) are always unauthenticated. With `--site-manifest`, the banner notes how many URLs were passed to Nuclei.
- **Score composition:** The numeric score reflects structured findings from headers, SSL, ports, **parsed Nuclei JSONL**, and optional **parsed ZAP JSON**. **Nikto** output remains in raw sections only (not scored). See [EXTENDED_SCANNING.md](EXTENDED_SCANNING.md).
- Raw details for headers, ports, and (when run) Nikto/Nuclei/ZAP output

The CLI scan summary prints the same Nuclei mode line.

---

## 🚀 CI/CD Integration

### GitLab CI (self-hosted)

The included `.gitlab-ci.yml` is meant for self-hosted runners with Docker available.

1. **Variables:** In the project’s CI/CD settings, set `TARGET_URL` (e.g. `https://your-app.example.com`). Override or add variables as needed for your pipeline.
2. **Runner:** Use tags (e.g. `self-hosted`, `shell`) so jobs run on machines that can build and run the Argus-Scan image.
3. **Artifacts:** Reports are saved under `reports/` and published as job artifacts (e.g. expire in 1 week).
4. **Branches:** The default pipeline triggers on `main` and `web`; adjust `only` in `.gitlab-ci.yml` to match your workflow.

---

## 🔬 How It Works

1. **Dependency check** (unless `--no-tool-check`): Ensures `nmap`, `nikto`, and `nuclei` are on `PATH`. If any are missing and `--full` is set, the run exits with instructions; otherwise it continues with Python-only checks.
2. **Port scan:** Nmap fast scan (`-F -sV`) on the resolved IP. Open ports are listed; known risky ports (e.g. 21, 23, 3389, 445, 3306) generate findings.
3. **Header scan:** HTTP GET to the target (scheme added if missing). Presence of security headers is checked; missing ones are reported with severity and remediation.
4. **SSL scan:** Connection to port 443; certificate expiry and basic validity are checked.
5. **Full scan (optional):** Runs Nikto (`-Tuning 123b`) and Nuclei. Nuclei writes **JSONL** via `-jle`; results are **parsed** into scored findings. With **`--site-manifest`**, Nuclei uses **`-list`** against a generated URL file instead of only `-u <target>`.
6. **Optional ZAP ingestion:** If **`--zap-report-json`** points to a ZAP traditional JSON file, alerts are aggregated and merged into the same findings list for scoring.
7. **Reporting:** Aggregates findings, computes score and grade, then writes CLI summary, Markdown, and HTML.

---

## 🔧 Troubleshooting

| Issue | What to do |
|-------|------------|
| **`ModuleNotFoundError` for `reporter` or `scanners`** | Run from the **repository root**: `python src/vapt.py ...`. Do not run from inside `src/` unless you adjust `PYTHONPATH` to include the project root or `src/`. |
| **“Missing external tools”** | Install Nmap/Nikto/Nuclei (see `setup.sh` messages or your distro docs), or run with `--no-tool-check` for Python-only checks. |
| **SSL/certificate errors on header check** | Use `--insecure` only for lab or self-signed targets. In production, fix the certificate or use a valid hostname. |
| **Nikto/Nuclei not run** | Use `--full`. Ensure the tools are on `PATH` or run via the Docker image. |
| **No or empty reports** | Confirm `--output` is writable and that the run completed (no early exit). Check the path reported in the “HTML report saved to” message. |
| **Cookie validation failed after capture** | The secret file may still be written; fix the session, point `AUTH_SCAN_VALIDATE_URL` at a path that distinguishes anonymous vs logged-in (after redirects), or set `AUTH_SCAN_SKIP_VALIDATE=1`. See messages from `capture_cookies_cdp.py` for details. |
| **`auth_scan_chrome.sh` shows usage with no URL** | Pass the start URL as the first argument **or** `export SCAN_TARGET=...` before running the script. |
| **Site manifest has no effect** | Nuclei only runs with **`--full`**. Without `--full`, Argus warns and skips Nuclei. |
| **ZAP findings missing from the score** | Ensure **`--zap-report-json`** points to an existing file (e.g. under `reports/`). HTML is optional and not parsed. |
| **Docker image name mismatch** | Use the same tag you built (e.g. `docker build -t argus-scan .` → `argus-scan:latest`). |
| **Parallel job table appears only after Ctrl+C** | Often **non-TTY** stdout (Docker logs, some IDE terminals): Rich `Live` buffers. Argus **reprints the table every ~1s** in that case. In a real TTY, `Live` uses **`screen=False`** so the table updates inline. |

---

## 🔮 Future Roadmap

- **Deep fuzzing:** Integration with directory brute-forcing tools (beyond curated URL manifests and ZAP baseline).
- **Authentication:** Broader options beyond Nuclei Secret Files (for example API tokens or custom headers without Chrome).
- **API security:** Dedicated checks for REST/GraphQL endpoints.

---

## ⚠️ Disclaimer

This tool is for **educational and authorized testing only**. Use it only on systems you own or have explicit permission to test. Unauthorized scanning may violate laws or policies.
