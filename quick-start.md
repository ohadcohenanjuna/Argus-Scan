# Quick start: site manifest and full scan

This guide walks you from **nothing** to a **full Argus scan** using a **YAML site manifest** (curated URLs for Nuclei). For deeper background, see the [README](README.md) and [EXTENDED_SCANNING.md](EXTENDED_SCANNING.md).

---

## What you will produce

| Artifact | Purpose |
|----------|---------|
| **`my-site.yaml`** | Lists URLs/paths Argus turns into a Nuclei URL list (`-list`). |
| **Optional: `nuclei-secret.*.yaml`** | Session cookies so Nuclei can hit **logged-in** pages. |
| **`reports/`** | HTML/Markdown dossiers plus raw tool output. |

---

## Prerequisites

- **Docker** (recommended), or a local install of Nmap, Nikto, and Nuclei plus Python deps from `requirements.txt`.
- From the **repository root** when running commands below.

---

## Step 1: Pick your scan target

Choose one canonical base URL, for example:

`https://app.example.com`

Use the **same** URL in the manifest (`base_url`), as `--target` when you run the scan, and when capturing cookies (if you need auth).

---

## Step 2: Collect URLs to put in the YAML

You are building a **deliberate list**, not an automatic crawl. Good sources:

1. **Click through the app** in a browser (especially after login) and copy the address bar for important screens: home, login, forgot password, search, settings, any page with a form.
2. **Ask your team** for routes that matter for security (admin, APIs exposed in the UI, download pages).
3. **Optional:** Export links from a sitemap or router config—still review the list before scanning.

For each URL, note:

- **Path only** (if it shares the same host as `base_url`) or a **full `https://...` URL** if it is another host.
- Whether it **needs login** (`requires_auth: true` in the YAML helps you remember to pass a secret file later).
- **Query strings** that matter (e.g. search: `/search?q=test`).

---

## Step 3: Create your manifest file

1. Copy the example:

   ```bash
   cp examples/site-manifest.example.yaml my-site.yaml
   ```

2. Edit **`my-site.yaml`**:

   - Set **`base_url`** to your app’s origin, with a trailing slash, e.g. `https://app.example.com/`.
   - Under **`urls`**, list what you collected. You can use either form:

     **Short form** (path is joined to `base_url`):

     ```yaml
     - /
     - path: /login
       category: login
       note: "Main sign-in"
     ```

     **Full URL** (for another host or exact query string):

     ```yaml
     - url: https://app.example.com/downloads?tech=sev-metal
       category: other
       note: "Resource downloads"
     ```

   - Use **`category`** and **`note`** for your own tracking; they do not change how Nuclei runs today, but they document intent.
   - Mark gated areas with **`requires_auth: true`** so you remember to use a cookie file in Step 4.

3. **Include the homepage** if you care about it: either `- /` or rely on the scan’s default (see Step 5)—`run_scan.sh` prepends `--target` to the list unless you disable that behavior in the CLI.

---

## Step 4 (optional): Log in and export cookies for Nuclei

Only if you listed **authenticated** URLs and want Nuclei to send a real session.

1. Install the small Python deps if you have not (for `auth_scan_chrome.sh`):

   ```bash
   python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
   ```

2. Run the Chrome helper against your **same** target URL, complete login in the browser, then press Enter when prompted:

   ```bash
   chmod +x auth_scan_chrome.sh
   ./auth_scan_chrome.sh "https://app.example.com/"
   ```

   This writes something like **`nuclei-secret.generated.yaml`** in the repo root (or a path you pass as the second argument).

3. Optional: set **`AUTH_SCAN_VALIDATE_URL`** to a **protected** URL if your start page is public but you need to verify the session against an app-only route. See the [README “Authenticated scan”](README.md#authenticated-scan) section.

---

## Step 5: Run the full scan

### Option A: One command with `run_scan.sh` (easiest)

From the repo root, with Docker:

```bash
chmod +x run_scan.sh
```

**Public pages only** (no cookie file):

```bash
SITE_MANIFEST=./my-site.yaml ./run_scan.sh "https://app.example.com/"
```

**With Nuclei authentication** (second argument = secret file path):

```bash
SITE_MANIFEST=./my-site.yaml ./run_scan.sh "https://app.example.com/" ./nuclei-secret.generated.yaml
```

**Faster scans** (more parallel load on the target):

```bash
VAPT_PARALLEL=1 SITE_MANIFEST=./my-site.yaml ./run_scan.sh "https://app.example.com/" ./nuclei-secret.generated.yaml
```

While that run is active, the first Ctrl+C asks workers to stop and cancels pending pool tasks; press Ctrl+C again to force immediate exit (the process does not wait for child tools to finish).

**Optional: ZAP baseline first**, then Argus (pulls the official ZAP image on first use):

```bash
RUN_ZAP=1 SITE_MANIFEST=./my-site.yaml ./run_scan.sh "https://app.example.com/"
```

The script builds the `argus-scan` image, runs **`--full`**, mounts your manifest at `/app/site-manifest.yaml`, and writes reports under **`./reports/`**. On macOS it opens the latest HTML report when finished.

### Option B: `docker run` only

Same idea, explicit flags:

```bash
docker build -t argus-scan .
mkdir -p reports

docker run --rm \
  -v "$(pwd)/reports:/app/reports" \
  -v "$(pwd)/my-site.yaml:/app/site-manifest.yaml:ro" \
  -v "$(pwd)/nuclei-secret.generated.yaml:/app/nuclei-secret.yaml:ro" \
  argus-scan:latest \
  --target "https://app.example.com/" \
  --full \
  --verbose \
  --site-manifest /app/site-manifest.yaml \
  --nuclei-secret-file /app/nuclei-secret.yaml
```

Omit the secret volume and `--nuclei-secret-file` if you do not need auth.

---

## Step 6: Open your reports

- **Directory:** `reports/<site-slug>/<scan-timestamp>/` (for example `reports/test.resources.anjuna.io/20250416_153045/`). The slug is derived from your target host.
- **Logs (parallel runs):** `logs/*.log` in that same folder (Nikto/Nuclei stream here instead of the console).
- **Files:** `vapt_report_<target-slug>_<timestamp>.html` and `.md` inside that session directory.
- The dossier lists findings from headers, SSL, ports, **parsed Nuclei** results, and **ZAP** if you passed ZAP JSON. **Nikto** output stays in the raw sections.

---

## Quick checklist

- [ ] `base_url` matches your app origin.
- [ ] Every important route is listed (login, search, forms, downloads, etc.).
- [ ] Authenticated routes either have a **nuclei secret** file or you accept that Nuclei may only see the login redirect.
- [ ] **`./run_scan.sh`** uses the **same** URL as `--target` as you used when collecting URLs (and when capturing cookies).
- [ ] You only scan systems you are **allowed** to test.

---

## If something fails

| Symptom | What to check |
|--------|----------------|
| Manifest seems ignored | You must use **`--full`** (the helper script does this). Without `--full`, Nuclei does not run. |
| ZAP docker errors | Use the current image; see [README](README.md#owasp-zap-reports). Set `ZAP_DOCKER_IMAGE` if your registry blocks GHCR. |
| “No report” | Ensure `reports/` exists and the container mount path is correct (`$(pwd)/reports`). |

For cookie capture and edge cases, see [README — Authenticated scan](README.md#authenticated-scan).
