<<<<<<< HEAD
# DroidTTP: Local APK Sample Console

DroidTTP is a local-first console for collecting and inspecting authorized Android application packages (APKs). Uploads are stored on the local instance, hashed, searchable, and statically inspected as ZIP archives. Uploaded sample code is never executed, and samples or extracted indicators are not sent to third parties.

Static results are leads for review, not a definitive malware verdict: declared permissions, components, and packaged strings do not prove runtime execution or malicious intent. Samples can be grouped into cases, searched, inspected, downloaded, deleted, and exported with their analysis.

---

## Visual & Interaction Design

DroidTTP features an advanced analyst workbench design inspired by bold editorial typography and expressive composition:
- **Blue-Led Palette:** Deep ink/navy (`#070d19`), electric cobalt (`#2563eb`), vivid blue (`#3b82f6`), pale ice surfaces (`#edf4ff`), and warm neutral backgrounds (`#f8fafc`).
- **Editorial Typography:** High-contrast headlines with tight letter-spacing, monospace technical tags for cryptographic hashes and package identifiers, and clear visual hierarchy.
- **Consistent Vector Icon System:** Pure SVG icon system across all navigation, actions, and status indicators without emoji.
- **Polished Micro-Interactions & Motion:** Fast, restrained page transitions (`pageReveal`), animated analysis progress, subtle card hover elevations, and full support for `prefers-reduced-motion`.
- **Responsive Layout:** Adaptive desktop, tablet, and mobile interface with a collapsible sidebar and accessible keyboard focus states (`:focus-visible`).

---

## Detailed Navigation & 9-Tab Analysis Workspace

The persistent sidebar provides structured access to all 9 CTI workflow domains:

1. **Overview:** Live metrics (active investigations, analyzed APKs, review queue, queue jobs), editorial hero with quick case/sample actions, bundled CSV summary, and real-time activity feeds. When no APK samples, pending mappings, or queue jobs exist, the four metrics and sample/review lists show a clearly marked, display-only demo preview. Demo entries are never saved, uploaded, analyzed, or included in reports; real sample/review data takes precedence.
2. **Cases:** Searchable and filterable investigations by status (Active, Closed, Archived), owner, source context, handling markings (`TLP:CLEAR`, `TLP:GREEN`, `TLP:AMBER`, `TLP:RED`), and tags.
3. **Samples:** Complete APK inventory with package name, version, cryptographic identities (SHA-256, SHA-1, MD5), duplicate detection (`duplicate ×2`), and analysis status.
4. **Analysis (Per-Sample 9 Tabs Workspace):**
   - **Summary:** Package identity, SDK targets, file metrics, triple cryptographic hashes, provenance, and TTP mapping distribution.
   - **Manifest:** Parsed text XML declarations, package attributes, SDK declarations, and structured JSON view with copy action.
   - **Permissions:** Searchable declared permissions categorized by risk (Dangerous, Special Access, Normal) with direct links to ATT&CK techniques.
   - **Components:** Activities, Services, Broadcast Receivers, Content Providers with exported status badges (`exported: true` / `false`).
   - **Certificates:** Inventory of META-INF signing artifacts (`.RSA`, `.DSA`, `.EC`, `.SF`, `MANIFEST.MF`) and signing presence notice.
   - **Strings:** Searchable extracted text strings from packaged resources with location inside the APK and copy controls.
   - **Network Indicators:** Defanged URLs (`hxxps://...`), domains (`domain[.]com`), and IP addresses with separate **Copy Defanged** and **Copy Raw** controls.
   - **Files & Binaries:** Compiled DEX bytecode files and native shared libraries (`.so`) categorized by CPU architecture (`arm64-v8a`, `armeabi-v7a`, `x86`).
   - **Tool Output:** Raw analysis JSON with one-click copy, worker runtime details, and explicit list of unsupported capabilities.
   - **ATT&CK Review Grid:** Review, confirm, reject, or defer candidate TTP mappings with editable analyst rationale and audit history.
5. **ATT&CK Mobile:** Searchable reviewed Android technique subset with conservative, low-confidence permission suggestions. Verify mappings against the official matrix before operational reporting.
6. **Evidence:** Master Evidence Register filterable by kind (Permissions, Components, URLs, Domains, IPs, Signing Artifacts, Notes) with defanged indicators and linked TTP badges.
7. **Reports:** Intelligence report hub for generating downloadable standalone HTML and structured CTI JSON reports with print-optimized CSS for instant vector PDF printing.
8. **Activity:** Chronological, immutable audit trail of uploads, analysis runs, mapping decisions, case edits, and exports.
9. **Settings:** Upload and worker limits, taxonomy status, integration status, and an optional sample retention period. When enabled, a running worker deletes expired samples and derived records hourly; `0` disables automatic deletion.

> **Account scope:** The current release uses one configured account shared by everyone with access to the instance. It does not provide separate user identities or per-user case access. Keep it on a trusted local network until multi-user accounts are implemented.

---

## Requirements

- **Operating System:** Windows 10/11, macOS, or Linux (Ubuntu 22.04+, Debian 12+, RHEL 9+)
- **Python:** 3.11 or newer
- **Docker:** Optional (supported via `docker-compose.yml` for self-hosted container deployments)

---

## Local Setup & Quickstart (Windows PowerShell)

1. Create a Python environment and install dependencies:

   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\python.exe -m pip install --upgrade pip
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   if (!(Test-Path .env)) { Copy-Item .env.example .env }
   ```

   If `.env` already exists, keep it; do not overwrite its credentials.

2. Edit `.env` before starting:
   - Set `DROIDTTP_USERNAME` and a private `DROIDTTP_PASSWORD` of at least 16 characters.
   - Set `DROIDTTP_SECRET` to a unique random value of at least 32 characters. Generate one in PowerShell with:
     ```powershell
     [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))
     ```

3. Start the web app and analysis worker together:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-local.ps1
   ```

   Open **<http://127.0.0.1:8000>** and sign in with the credentials from `.env`. If port 8000 is occupied, use:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-local.ps1 -Port 8001
   ```

   Press Ctrl+C to stop the server and its worker. If you prefer separate terminals, start `.\.venv\Scripts\python.exe -m app.queue_worker` in one and `.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000` in the other.

### Sample workflow

1. Create a case, then select **Samples → Add Sample** and choose the case and APK file.
2. Intake accepts a readable ZIP/APK containing `AndroidManifest.xml`; invalid files receive an error before they are added to the inventory. Upload size and archive inspection limits are enforced.
3. The original APK is stored under `data/samples` by default (or under `DROIDTTP_DATA_DIR/samples`). The worker performs static inspection only.
4. Search or filter the inventory, inspect package metadata, hashes, manifest declarations, strings, file entries, and extracted indicators. Download or delete a sample from the inventory or inspection view. Deletion also removes its derived findings.
5. Export the inventory as CSV, or export an individual sample or case report as HTML/JSON.

No example or dataset-derived sample records are created on startup. Existing legacy dataset-only records without an uploaded APK are removed on startup; real stored APKs and user-uploaded samples are preserved.

### Dataset Lab

The **Dataset Lab** browses the bundled `data/TTP Dataset.zip` CSV as a separate, read-only metadata catalogue. It currently contains 15,736 source rows and 15,475 unique package names, with source labels `0` and `1`; labels are displayed verbatim because their meaning is not asserted here. Search by package name or source SHA-256, filter by label, inspect the bounded profile fields, and export the filtered rows to CSV. Certificate subject/issuer identity and contact/address-like CSV columns are not exposed in profiles. Dataset counts and per-label feature means are descriptive statistics only; DroidTTP includes no trained classifier, so the page makes no prediction or accuracy claim. The dataset contains no APK binaries and its rows are never inserted into the APK inventory.

### macOS / Linux

Install requirements in a virtual environment and configure `.env` as above. Run the web app and queue worker in separate terminals:

```bash
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
python -m app.queue_worker
```

The worker reads only its data directory and analysis timeout from `.env`; it does not load the app password or session secret.

---

## Production Deployment with Docker Compose

DroidTTP includes a complete containerized production stack with an Nginx reverse proxy, automated TLS generation, rate limiting, and health probes:

```bash
# Automated single-command deployment
./scripts/deploy.sh

# Or with Docker Compose directly:
docker compose up -d --build
```

- **Web Interface (HTTPS):** `https://localhost` (or server IP)
- **Liveness Probe:** `https://localhost/healthz`
- **Readiness Probe:** `https://localhost/readyz`

See [`DEPLOYMENT.md`](DEPLOYMENT.md) for complete production documentation, including bare-metal systemd unit installation, air-gapped deployment, and Nginx SSL configuration.

---

## Automated Backups & Disaster Recovery

- **Take Hot Backup:**
  - Linux/macOS: `./scripts/backup.sh`
  - Windows: `.\scripts\backup.ps1`
  *Produces an atomic SQLite database snapshot, archives private APK samples, and generates a SHA-256 verification hash.*

- **Restore from Backup:**
  - Linux/macOS: `./scripts/restore.sh <backup-archive.tar.gz> [target-dir]`
  - Windows: `.\scripts\restore.ps1 -ArchivePath <backup-archive.zip>`
  *Validates SHA-256 integrity, transactionally restores data, and executes SQLite `PRAGMA integrity_check`.*

---

## Running Automated Tests

Run the complete Python test suite covering health probes, session signatures, APK parsing, heuristic rules, case lifecycles, and E2E workflows:

```powershell
.\.venv\Scripts\python.exe -m unittest discover tests
```

---

## Project Layout

```text
app/
  main.py                 FastAPI application, routes, schema migrations, and session management
  analyzer.py             Bounded static APK archive & manifest inspector
  analysis_worker.py      Bounded parser subprocess used by the queue worker
  queue_worker.py         Durable queue consumer; separate isolated deployment service
  taxonomy.py             Reviewed MITRE ATT&CK Android subset and conservative rules
  static/                 Redesigned blue-led workbench UI
    index.html            Semantic HTML with inline SVG icon system & 9 analysis tabs
    styles.css            Complete editorial styling, animations, and responsive system
    app.js                Interactive controller, tab switching, filters, and modals
nginx/                    Hardened Nginx reverse proxy configurations and TLS scripts
deployment/               Systemd service units for bare-metal Linux
scripts/                  Automated deployment, hot backup, and restore utilities
tests/                    Automated unit, integration, and E2E test suites
data/                     Private database and uploaded sample storage (created at runtime)
DEPLOYMENT.md             Full production deployment and operations manual
README.md                 Workbench reference and quickstart guide
```
=======
# Droid-TTP
Mapping Android Applications to MITRE ATT&amp;CK TTPs for Cyber Threat Intelligence
>>>>>>> 9ab07b5e8297abc38d4801121b510c20bbc81f94
