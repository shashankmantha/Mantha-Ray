# Mantha Ray

Mantha Ray is a local static malware-triage application for inspecting suspicious folders without executing their contents.

It inventories files, calculates hashes, scans for known signatures with ClamAV, identifies executable capabilities with capa, and extracts strings from eligible Windows executables with FLOSS. Analysis runs inside a hardened, network-disabled Docker container, while a local web interface presents progress, saved scans, reports, and per-file results.

> Static analysis can identify useful indicators, but it cannot prove that a file is safe.

## Features

* Local browser-based interface
* Persistent scan history
* Live analysis-stage tracker
* Expandable artifact and directory tree
* Per-file analyzer coverage
* Weighted capa risk scoring
* ClamAV signature detection
* FLOSS string extraction for eligible PE files
* SHA-256 hashing and file inventory
* Markdown and JSON reports
* Raw analyzer output retention
* Scan cancellation
* Read-only source mounting
* Network-disabled analysis
* Resource-limited Docker execution

## Analysis pipeline

Mantha Ray processes a selected folder through five stages:

1. **Inventory**

   * Walks the directory tree
   * Records file type, size, permissions, and routing class
   * Calculates SHA-256 hashes
   * Enforces file-count, size, and depth limits

2. **ClamAV**

   * Scans files against the signatures included in the analysis image
   * Reports known detections and scan errors

3. **capa**

   * Analyzes supported PE and ELF binaries
   * Identifies capabilities such as process manipulation, networking, persistence, and cryptography
   * Assigns weighted risk based on capability type and supporting evidence

4. **FLOSS**

   * Extracts static, stack, tight, and decoded strings from eligible PE files
   * Does not run against unsupported file types such as ELF binaries

5. **Report**

   * Produces machine-readable and human-readable case artifacts
   * Records incomplete stages and coverage gaps

## Safety model

Mantha Ray is designed to inspect files without executing them.

The analysis container is launched with:

* Networking disabled
* A read-only container filesystem
* The selected input folder mounted read-only
* Linux capabilities dropped
* `no-new-privileges` enabled
* CPU, memory, and process limits
* A bounded temporary filesystem mounted with `noexec`
* Results written to a separate output directory

The source folder and results folder cannot overlap.

These controls reduce risk, but they do not make hostile files harmless. Docker relies on the host kernel and should not be treated as a perfect security boundary. Analyze untrusted material inside a dedicated, disposable VM whenever possible.

For higher-risk samples:

* Disable the VM network adapter at the hypervisor
* Disable shared folders, clipboard sharing, and drag-and-drop
* Take a clean VM snapshot first
* Do not launch samples through Wine or another runtime
* Do not treat a clean static report as authorization to execute a file

## Requirements

Mantha Ray currently targets Linux.

Required software:

* Git
* Python 3
* Python virtual-environment support
* Docker
* Node.js
* npm

Docker must be running and accessible to the current user.

Check the required tools:

```bash
git --version
python3 --version
docker --version
docker info
node --version
npm --version
```

Access to the Docker daemon is security-sensitive. Membership in the Docker group is effectively equivalent to elevated host access.

## Installation from source

Clone the repository:

```bash
git clone https://github.com/shashankmantha/Mantha-Ray.git malware-scanner
cd Mantha-Ray
```

Create and activate a Python virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the Python application:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -e .
```

Build the web interface:

```bash
cd frontend
npm ci
npm run build
cd ..
```

Build the analysis image using the repository’s `Containerfile`:

```bash
docker build \
  --file Containerfile \
  --tag static-triage:core \
  .
```

Confirm that the image contains the progress-enabled scanner:

```bash
docker run --rm \
  --network none \
  static-triage:core \
  scan --help
```

The output should include:

```text
--progress-jsonl
```

## Running Mantha Ray

If the virtual environment is active:

```bash
mantha-ray
```

Otherwise:

```bash
.venv/bin/mantha-ray
```

Mantha Ray starts a local authenticated web service and opens the interface in your default browser.

To start it without automatically opening a browser:

```bash
.venv/bin/mantha-ray web --no-browser
```

To use a specific loopback port:

```bash
.venv/bin/mantha-ray web --port 8080
```

## Starting a scan

1. Select **New scan**.
2. Choose the folder containing the files to inspect.
3. Choose a separate results directory.
4. Select **Start secure scan**.
5. Monitor the live stage tracker.
6. Review the artifact tree and completed report.

The default results location is:

```text
~/mantha-ray-results
```

Do not place the results directory inside the scanned folder or the scanned folder inside the results directory.

For very large applications, consider scanning suspicious installers, launchers, crack directories, DLLs, or executable folders first. Full game or application directories may contain tens of thousands of files and can take significantly longer.

## Understanding results

### Overall case status

| Status                     | Meaning                                                                                                                                 |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **No Indicators Detected** | All configured stages completed without a signature detection or review-level static indicator. This does not prove the files are safe. |
| **Needs Review**           | Static evidence crossed the review threshold or otherwise requires manual inspection.                                                   |
| **High Concern**           | Stronger capability combinations or other high-risk evidence were identified.                                                           |
| **Known Detection**        | ClamAV reported a known signature match.                                                                                                |
| **Incomplete**             | One or more stages failed, timed out, were unavailable, or exceeded configured limits.                                                  |

### Artifact risk

| Risk       | Meaning                                                                               |
| ---------- | ------------------------------------------------------------------------------------- |
| **Clean**  | No mapped file-level indicator was recorded.                                          |
| **Low**    | Informational behavior was found, such as a common process-lifecycle capability.      |
| **Medium** | The file has review flags or capa evidence that requires closer inspection.           |
| **High**   | A known signature or high-concern capability assessment was associated with the file. |

Directory rows inherit the highest risk of any artifact beneath them.

### Analyzer coverage badges

A badge indicates that an analyzer covered the file.

The absence of a badge can mean the analyzer was not applicable. For example:

* capa can inspect supported PE and ELF binaries.
* FLOSS is intended for eligible PE files.
* A text document will not normally receive capa or FLOSS coverage.

Analyzer coverage does not mean the file is safe. It only describes which tools examined it.

### capa results

A capa capability is a description of observed program behavior, not automatically a malware verdict.

For example:

```text
terminate process
risk 1 — informational
```

Process termination is common in legitimate software. Mantha Ray’s weighting policy prevents low-context lifecycle behavior from independently forcing a case into review.

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

* `report.md` — human-readable report
* `report.json` — structured report for automation
* `files.jsonl` — one inventory record per artifact
* `manifest.json` — case metadata and tool information
* `raw/` — bounded analyzer output and per-file results
* `logs/scanner.log` — scanner activity log
* `web-session.json` — optional interface metadata used for persisted scan history

The report and inventory should be treated as untrusted evidence when filenames or embedded strings originate from suspicious files.

## Saved scans

Mantha Ray indexes completed cases from the selected results directory.

Saved scans appear in the left sidebar and can be reopened after restarting the application. Scan history is filesystem-backed; no external database or cloud service is required.

The interface ignores malformed, incomplete, or symbolically linked case directories that do not satisfy the expected case structure.

## Updating the ClamAV database

The ClamAV database is included when the analysis image is built.

Mantha Ray intentionally treats an excessively old signature database as an incomplete scan. If ClamAV reports that its database is older than the allowed age, rebuild the image while online:

```bash
docker build \
  --pull \
  --no-cache \
  --file Containerfile \
  --tag static-triage:core \
  .
```

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

### Docker is unavailable

Confirm that Docker is running:

```bash
docker info
```

Then verify that the current user can launch a container:

```bash
docker run --rm hello-world
```

### `--progress-jsonl` is not recognized

The web application is using an older analysis image. Rebuild it from the current source:

```bash
docker build \
  --file Containerfile \
  --tag static-triage:core \
  .
```

Confirm the flag exists:

```bash
docker run --rm \
  --network none \
  static-triage:core \
  scan --help \
  | grep progress-jsonl
```

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

* File hashing
* ClamAV scanning
* Per-binary capa analysis
* FLOSS extraction

The interface limits analyzer work and reports skipped or timed-out files as coverage gaps rather than silently treating them as clean.

### A clean file appears as low risk

A file may contain an informational capa capability without requiring review. Low risk means a weak static behavior was observed; it is not the same as a known detection.

## Current limitations

* Static analysis cannot observe runtime-only behavior.
* Packed or encrypted executables can hide capabilities and strings.
* ClamAV coverage depends on the age and contents of its signature database.
* capa matches describe behavior and require context.
* FLOSS currently targets eligible PE files.
* Very large folders may hit file, size, output, or time limits.
* Password-protected archives must be handled separately before their contents can be inspected.
* No static result should be treated as proof that execution is safe.

## Roadmap

Planned work includes:

* Expanded multi-file and mixed-format test fixtures
* File-level evidence details in the artifact tree
* High, medium, low, and clean dashboard totals
* Improved large-tree navigation and filtering
* One-command local installer
* Prebuilt release packages
* Automatically refreshed analysis images
* Optional YARA support
* Future emulation and sandbox integrations
* Final retro-inspired interface and color-system pass

## Responsible use

Mantha Ray is intended for defensive security analysis, education, incident response, and authorized research.

Only inspect files that you are authorized to possess and analyze. Do not use the project to distribute malware, bypass access controls, or execute suspicious software on systems you do not own or administer.

When in doubt, preserve the sample, keep it isolated, and escalate it for professional review.
