# Mantha Ray

Mantha Ray is a local static malware-triage application for inspecting suspicious folders without executing their contents.

It inventories files, calculates hashes, scans for known signatures with ClamAV, identifies executable capabilities with capa, and extracts strings from eligible Windows executables with FLOSS. Analysis runs inside a hardened, network-disabled Docker container, while a local web interface presents live progress, saved scans, reports, and per-file results.

> Static analysis can identify useful indicators, but it cannot prove that a file is safe.

## Features

- Local browser-based interface
- Persistent scan history
- Live analysis-stage tracker and activity console
- Expandable artifact and directory tree
- Per-file analyzer coverage
- Weighted capa risk scoring
- ClamAV signature detection
- FLOSS string extraction for eligible PE files
- SHA-256 hashing and file inventory
- Markdown and JSON reports
- Raw analyzer output retention
- Scan cancellation
- Read-only source mounting
- Network-disabled analysis
- Resource-limited Docker execution

## Analysis pipeline

Mantha Ray processes a selected folder through five stages:

1. **Inventory**
   - Walks the directory tree
   - Records file type, size, permissions, and routing class
   - Calculates SHA-256 hashes
   - Enforces file-count, size, and depth limits
2. **ClamAV**
   - Scans files against the signatures included in the analysis image
   - Reports known detections and scan errors
3. **capa**
   - Analyzes supported PE and ELF binaries
   - Identifies capabilities such as process manipulation, networking, persistence, and cryptography
   - Assigns weighted risk based on capability type and supporting evidence
4. **FLOSS**
   - Extracts static, stack, tight, and decoded strings from eligible PE files
   - Does not run against unsupported file types such as ELF binaries
5. **Report**
   - Produces machine-readable and human-readable case artifacts
   - Records incomplete stages and coverage gaps

## Safety model

Mantha Ray is designed to inspect files without executing them.

The analysis container is launched with:

- Networking disabled
- A read-only container filesystem
- The selected input folder mounted read-only
- Linux capabilities dropped
- `no-new-privileges` enabled
- CPU, memory, and process limits
- A bounded temporary filesystem mounted with `noexec`
- Results written to a separate output directory

The source folder and results folder cannot overlap.

These controls reduce risk, but they do not make hostile files harmless. Docker relies on the host kernel and should not be treated as a perfect security boundary. Analyze untrusted material inside a dedicated, disposable VM whenever possible.

For higher-risk samples:

- Disable the VM network adapter at the hypervisor
- Disable shared folders, clipboard sharing, and drag-and-drop
- Take a clean VM snapshot first
- Do not launch samples through Wine or another runtime
- Do not treat a clean static report as authorization to execute a file

## Requirements

Mantha Ray currently targets Linux.

Required software:

- Git
- Python 3
- Python virtual-environment support
- Tkinter
- Docker Engine and the Docker CLI

Node.js and npm are only required when modifying or rebuilding the frontend. The repository includes compiled frontend assets for normal installation.

### Fedora and Nobara

Install the required system packages:

```bash
sudo dnf install \
  git \
  python3 \
  python3-pip \
  python3-tkinter \
  docker-cli \
  moby-engine
```

Start Docker and enable it at boot:

```bash
sudo systemctl enable --now docker
```

Add the current user to the Docker group:

```bash
sudo usermod -aG docker "$USER"
```

Log out and back in before continuing so the new group membership takes effect.

### Ubuntu and Debian

Install the required system packages:

```bash
sudo apt update
sudo apt install \
  git \
  python3 \
  python3-venv \
  python3-pip \
  python3-tk \
  docker.io
```

Start Docker and enable it at boot:

```bash
sudo systemctl enable --now docker
```

Add the current user to the Docker group:

```bash
sudo usermod -aG docker "$USER"
```

Log out and back in before continuing.

### Arch Linux

Install the required system packages:

```bash
sudo pacman -S --needed \
  git \
  python \
  python-pip \
  tk \
  docker
```

Start Docker and enable it at boot:

```bash
sudo systemctl enable --now docker
```

Add the current user to the Docker group:

```bash
sudo usermod -aG docker "$USER"
```

Log out and back in before continuing.

### Verify the prerequisites

From the repository root, run:

```bash
./scripts/check-requirements.sh
```

You can also verify Docker access directly:

```bash
docker info
docker run --rm hello-world
```

Do not run Mantha Ray with `sudo`. The application expects the current user to have direct access to Docker.

Access to the Docker daemon is security-sensitive. Membership in the Docker group is effectively equivalent to elevated host access.

## Installation from source

Clone the repository:

```bash
git clone https://github.com/shashankmantha/Mantha-Ray.git malware-scanner
cd malware-scanner
```

Check the host requirements:

```bash
./scripts/check-requirements.sh
```

Run the setup workflow:

```bash
./scripts/setup.sh
```

The setup script creates the repository-local Python virtual environment and installs Mantha Ray with its required host-side dependencies. Normal users do not need to activate the virtual environment manually.

Confirm that the installation and bundled frontend are present:

```bash
test -x .venv/bin/mantha-ray
test -f src/static_triage/web_dist/index.html
```

Build the analysis image:

```bash
docker build \
  --pull \
  --file Containerfile \
  --tag static-triage:core \
  .
```

The initial image build requires an internet connection and may take several minutes. It installs ClamAV, capa, FLOSS, their supporting rules, and the current ClamAV signature database.

Verify the analysis image:

```bash
docker run --rm \
  --network none \
  static-triage:core \
  scan --help
```

The scanner help should include:

```text
--progress-jsonl
```

Check the bundled ClamAV engine and database version:

```bash
docker run --rm \
  --network none \
  --entrypoint clamscan \
  static-triage:core \
  --version
```

After the image has been built, Mantha Ray runs analysis containers with networking disabled.

### Frontend development

This section is only necessary when changing files under `frontend/`.

Install Node.js and npm using the package manager for your distribution, then let the setup workflow install and build the frontend:

```bash
./scripts/setup.sh --build-frontend
```

Alternatively, build it directly:

```bash
cd frontend
npm ci
npm run build
cd ..
```

The production application uses the compiled assets stored under:

```text
src/static_triage/web_dist/
```

## Running Mantha Ray

From the repository root, launch Mantha Ray with:

```bash
./mantha-ray.sh
```

The launcher automatically uses the repository's virtual environment. Manual activation is not required.

Mantha Ray starts an authenticated loopback web service and opens the interface in the default browser.

Advanced command-line options remain available through the virtual-environment executable. For example:

```bash
.venv/bin/mantha-ray web --no-browser
.venv/bin/mantha-ray web --port 8080
```

## Starting a scan

1. Select **New scan**.
2. Choose the folder containing the files to inspect.
3. Choose a separate results directory.
4. Select **Start secure scan**.
5. Monitor the stage tracker and live Activity console.
6. Pause or resume auto-scroll as needed, or copy the activity log.
7. Review the artifact tree and completed report.

The default results location is:

```text
~/mantha-ray-results
```

Do not place the results directory inside the scanned folder or the scanned folder inside the results directory.

For very large applications, consider scanning suspicious installers, launchers, crack directories, DLLs, or executable folders first. Full game or application directories may contain tens of thousands of files and can take significantly longer.

## Understanding results

### Overall case status

| Status | Meaning |
| --- | --- |
| **No Indicators Detected** | All configured stages completed without a signature detection or review-level static indicator. This does not prove the files are safe. |
| **Needs Review** | Static evidence crossed the review threshold or otherwise requires manual inspection. |
| **High Concern** | Stronger capability combinations or other high-risk evidence were identified. |
| **Known Detection** | ClamAV reported a known signature match. |
| **Incomplete** | One or more stages failed, timed out, were unavailable, or exceeded configured limits. |

### Artifact risk

| Risk | Meaning |
| --- | --- |
| **Clean** | No mapped file-level indicator was recorded. |
| **Low** | Informational behavior was found, such as a common process-lifecycle capability. |
| **Medium** | The file has review flags or capa evidence that requires closer inspection. |
| **High** | A known signature or high-concern capability assessment was associated with the file. |

Directory rows inherit the highest risk of any artifact beneath them.

### Analyzer coverage badges

A badge indicates that an analyzer covered the file.

The absence of a badge can mean the analyzer was not applicable. For example:

- capa can inspect supported PE and ELF binaries.
- FLOSS is intended for eligible PE files.
- A text document will not normally receive capa or FLOSS coverage.

Analyzer coverage does not mean the file is safe. It only describes which tools examined it.

### capa results

A capa capability is a description of observed program behavior, not automatically a malware verdict.

For example:

```text
terminate process
risk 1 — informational
```

Process termination is common in legitimate software. Mantha Ray's weighting policy prevents low-context lifecycle behavior from independently forcing a case into review.

Capabilities become more important when they appear in suspicious combinations or alongside stronger evidence.

## Case output

Each scan creates a case directory similar to:

```text
case-20260925T171612Z-9e778e07/
├── files.jsonl
├── manifest.json
├── report.json
├── report.md
├── web-session.json
├── logs/
│   └── scanner.log
└── raw/
    ├── clamav/
    ├── capa/
    └── floss/
```

### Important files

- `report.md` — human-readable report
- `report.json` — structured report for automation
- `files.jsonl` — one inventory record per artifact
- `manifest.json` — case metadata and tool information
- `raw/` — bounded analyzer output and per-file results
- `logs/scanner.log` — scanner activity log
- `web-session.json` — optional interface metadata used for persisted scan history

The report and inventory should be treated as untrusted evidence when filenames or embedded strings originate from suspicious files.

## Saved scans

Mantha Ray indexes completed cases from the selected results directory.

Saved scans appear in the left sidebar and can be reopened after restarting the application. Scan history is filesystem-backed; no external database or cloud service is required.

The interface ignores malformed, incomplete, or symbolically linked case directories that do not satisfy the expected case structure.

## Updating the ClamAV database

The ClamAV database is included when the analysis image is built.

Mantha Ray intentionally treats a signature database older than 7 days as an incomplete scan, and ClamAV is shown as failed for every file. Refresh it by running setup again while online:

```bash
./scripts/setup.sh
```

The signature download has its own image layer keyed to the build date, so this re-downloads signatures at most once per day and reuses the cached capa and FLOSS installation.

Verify the database and engine version:

```bash
docker run --rm \
  --network none \
  --entrypoint clamscan \
  static-triage:core \
  --version
```

## Development

### Run the Python tests

From the repository root:

```bash
PYTHONPATH="$PWD/src" python3 -m unittest discover \
  -s tests \
  -p 'test_*.py' \
  -v
```

### Type-check and build the frontend

```bash
cd frontend
npm run build
cd ..
```

The frontend build runs TypeScript checking before producing the bundled web assets.

### Run the development frontend

```bash
cd frontend
npm run dev
```

The production application normally serves the bundled files generated by `npm run build`.

## Project structure

```text
malware-scanner/
├── Containerfile
├── mantha-ray.sh
├── scripts/
│   ├── check-requirements.sh
│   └── setup.sh
├── frontend/
│   ├── index.html
│   ├── package.json
│   └── src/
│       ├── main.ts
│       └── styles.css
├── src/
│   └── static_triage/
│       ├── cli.py
│       ├── scanner.py
│       ├── inventory.py
│       ├── clamav.py
│       ├── capa.py
│       ├── floss.py
│       ├── reporting.py
│       ├── host_scan.py
│       ├── web_api.py
│       ├── web_service.py
│       └── web_dist/
├── tests/
├── pyproject.toml
└── README.md
```

## Troubleshooting

### Permission denied when running a script

Git normally preserves executable permissions. If the scripts cannot be executed, restore them with:

```bash
chmod +x \
  scripts/check-requirements.sh \
  scripts/setup.sh \
  mantha-ray.sh
```

Then retry:

```bash
./scripts/setup.sh
```

### Docker permission denied or unavailable

Confirm that Docker is running:

```bash
sudo systemctl enable --now docker
docker info
```

If access is still denied, add the current account to the Docker group:

```bash
sudo usermod -aG docker "$USER"
```

Sign out and back in before retrying.

Do not repeatedly prefix Mantha Ray with `sudo`. The application and its result files should remain owned by the normal user.

### Missing virtual environment

Run the setup workflow:

```bash
./scripts/setup.sh
```

The `./mantha-ray.sh` launcher automatically uses the repository's virtual environment after setup completes. Manual activation is not required.

### Missing web interface

Confirm that the bundled frontend exists:

```bash
test -f src/static_triage/web_dist/index.html
```

If the file is missing and the frontend development requirements are installed, rebuild it with:

```bash
./scripts/setup.sh --build-frontend
```

### `--progress-jsonl` is not recognized

The web application is using an older analysis image. Rebuild it from the current source:

```bash
docker build \
  --pull \
  --file Containerfile \
  --tag static-triage:core \
  .
```

Confirm the flag exists:

```bash
docker run --rm \
  --network none \
  static-triage:core \
  scan --help | grep progress-jsonl
```

### Old ClamAV signatures

If every file shows ClamAV as failed, the image's signatures are probably more than 7 days old. Run setup again while online; it refreshes the signatures without reinstalling the other tools:

```bash
./scripts/setup.sh
```

If you build the image by hand, pass a new value for `CLAMAV_DB_REFRESH` (for example, `--build-arg CLAMAV_DB_REFRESH=$(date -u +%Y-%m-%d)`), or use `--no-cache` to rebuild everything.

### ClamAV exits with code 2

Inspect the saved output:

```bash
cat ~/mantha-ray-results/<case-id>/raw/clamav/stdout.txt
cat ~/mantha-ray-results/<case-id>/raw/clamav/stderr.txt
```

If the database is too old, rebuild the image with `--no-cache`.

### Python cannot import `tests`

Run the test command from the repository root:

```bash
cd malware-scanner
PYTHONPATH="$PWD/src" python3 -m unittest discover \
  -s tests \
  -p 'test_*.py' \
  -v
```

### The source and results folders overlap

Choose two independent locations. For example:

```text
Source:  ~/samples/suspicious-folder
Results: ~/mantha-ray-results
```

Do not save results beneath the source folder.

### A scan takes a long time

Large folders can require substantial time for:

- File hashing
- ClamAV scanning
- Per-binary capa analysis
- FLOSS extraction

The interface limits analyzer work and reports skipped or timed-out files as coverage gaps rather than silently treating them as clean.

### A clean file appears as low risk

A file may contain an informational capa capability without requiring review. Low risk means a weak static behavior was observed; it is not the same as a known detection.

## Current limitations

- Static analysis cannot observe runtime-only behavior.
- Packed or encrypted executables can hide capabilities and strings.
- ClamAV coverage depends on the age and contents of its signature database.
- capa matches describe behavior and require context.
- FLOSS currently targets eligible PE files.
- Very large folders may hit file, size, output, or time limits.
- Password-protected archives must be handled separately before their contents can be inspected.
- No static result should be treated as proof that execution is safe.

## Roadmap

Planned work includes:

- Expanded multi-file and mixed-format test fixtures
- File-level evidence details in the artifact tree
- High, medium, low, and clean dashboard totals
- Improved large-tree navigation and filtering
- Prebuilt release packages
- Automatically refreshed analysis images
- Optional YARA support
- Future emulation and sandbox integrations
- Final retro-inspired interface and color-system pass

## Responsible use

Mantha Ray is intended for defensive security analysis, education, incident response, and authorized research.

Only inspect files that you are authorized to possess and analyze. Do not use the project to distribute malware, bypass access controls, or execute suspicious software on systems you do not own or administer.

When in doubt, preserve the sample, keep it isolated, and escalate it for professional review.