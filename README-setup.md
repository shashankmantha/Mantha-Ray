## Requirements

Mantha Ray currently targets Linux. Normal setup requires:

- Git
- Python 3.11 or newer
- Python virtual-environment support
- Python Tkinter support
- Docker Engine
- Docker CLI
- Docker Buildx

Docker must be running and accessible to the current user. Docker group
membership is effectively equivalent to elevated host access; only grant it
to trusted accounts.

Node.js and npm are not required for normal installation. Mantha Ray includes
a prebuilt web interface under `src/static_triage/web_dist`.

Node.js 20.19+, 22.12+, or newer and npm are only required when rebuilding
the frontend from source.

The requirements checker reports missing software and prints installation
hints for Fedora/Nobara, Ubuntu/Debian, Arch, and openSUSE:

```bash
./scripts/check-requirements.sh
```

To also check the optional frontend development requirements:

```bash
./scripts/check-requirements.sh --frontend
```

The checker does not install packages, invoke `sudo`, change group membership,
or modify the host.

## Quick setup

Clone the repository:

```bash
git clone https://github.com/shashankmantha/Mantha-Ray.git malware-scanner
cd malware-scanner
```

Run the setup workflow:

```bash
./scripts/setup.sh
```

The setup script:

1. Validates the runtime requirements and Docker access.
2. Creates or reuses `.venv`.
3. Installs the available Mantha Ray runtime extras from `pyproject.toml`.
4. Uses the bundled web interface.
5. Builds `static-triage:core` from `Containerfile`.
6. Verifies that the image contains the progress-enabled scanner.

The process is repeatable. Existing virtual environments and Docker build
layers are reused when valid.

Launch Mantha Ray without manually activating the virtual environment:

```bash
./mantha-ray.sh
```

Additional CLI arguments are forwarded to Mantha Ray. For example:

```bash
./mantha-ray.sh web --no-browser
./mantha-ray.sh web --port 8080
```

## Rebuilding the frontend

Frontend rebuilding is only necessary after changing files under `frontend/`.

Check the additional development requirements:

```bash
./scripts/check-requirements.sh --frontend
```

Run setup with frontend rebuilding enabled:

```bash
./scripts/setup.sh --build-frontend
```

This installs the locked npm dependencies, type-checks the TypeScript source,
builds the frontend, and then continues with the normal container build and
verification process.

The generated frontend assets under `src/static_triage/web_dist` must be
committed so regular users can install Mantha Ray without Node.js or npm.

## Manual installation

If the automated setup cannot be used, create the Python environment manually:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip setuptools wheel
.venv/bin/python -m pip install -e '.[web,desktop]'
```

Confirm that the bundled frontend exists:

```bash
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

Verify the analysis image:

```bash
docker run --rm \
  --network none \
  static-triage:core \
  scan --help
```

The scanner help must include:

```text
--progress-jsonl
```

Launch Mantha Ray:

```bash
./mantha-ray.sh
```

## Setup troubleshooting

### Permission denied when running a script

Git normally preserves the executable permissions. If the scripts cannot be
executed, restore them with:

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

### Docker permission denied

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

Do not repeatedly prefix Mantha Ray with `sudo`. The application and its
result files should remain owned by the normal user.

### Missing virtual environment

Run the setup workflow:

```bash
./scripts/setup.sh
```

The `./mantha-ray.sh` launcher automatically uses the repository’s virtual
environment after setup completes. Manual activation is not required.

### Missing web interface

Confirm that the bundled frontend exists:

```bash
test -f src/static_triage/web_dist/index.html
```

If the file is missing and the frontend development requirements are
installed, rebuild it with:

```bash
./scripts/setup.sh --build-frontend
```

### Old ClamAV signatures

Rebuild the image with updated base-image layers and without the build cache:

```bash
docker build \
  --pull \
  --no-cache \
  --file Containerfile \
  --tag static-triage:core \
  .
```