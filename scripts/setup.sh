#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIRECTORY="$(
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
  pwd
)"
PROJECT_ROOT="$(
  cd -- "$SCRIPT_DIRECTORY/.."
  pwd
)"
VIRTUAL_ENVIRONMENT="$PROJECT_ROOT/.venv"
FRONTEND_DIRECTORY="$PROJECT_ROOT/frontend"
IMAGE_NAME="static-triage:core"
build_frontend=false

usage() {
  cat <<'EOF'
Usage: ./scripts/setup.sh [--build-frontend]

Creates the Python environment and analysis image needed by Mantha Ray.
The committed frontend bundle is used by default.

Options:
  --build-frontend  Install locked npm packages and rebuild web_dist.
  -h, --help        Show this help message.
EOF
}

while (($# > 0)); do
  case "$1" in
    --build-frontend)
      build_frontend=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown option: %s\n\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac

  shift
done

on_error() {
  local exit_code="$?"
  local line_number="${BASH_LINENO[0]:-unknown}"

  printf '\nSetup failed near line %s (exit %s).\n' \
    "$line_number" \
    "$exit_code" \
    >&2
  printf 'Fix the reported error and run setup again.\n' >&2
}

trap on_error ERR

step() {
  printf '\n==> %s\n' "$1"
}

cd -- "$PROJECT_ROOT"

step "Checking host requirements"

requirement_arguments=()

if [[ "$build_frontend" == true ]]; then
  requirement_arguments+=(--frontend)
fi

bash "$SCRIPT_DIRECTORY/check-requirements.sh" \
  "${requirement_arguments[@]}"

step "Preparing the Python virtual environment"

if [[ -e "$VIRTUAL_ENVIRONMENT" && ! -x "$VIRTUAL_ENVIRONMENT/bin/python" ]]; then
  printf '%s\n' \
    "Existing .venv is incomplete: $VIRTUAL_ENVIRONMENT" \
    'Move or remove it, then run setup again.' \
    >&2
  exit 1
fi

if [[ ! -x "$VIRTUAL_ENVIRONMENT/bin/python" ]]; then
  python3 -m venv "$VIRTUAL_ENVIRONMENT"
else
  printf 'Reusing %s\n' "$VIRTUAL_ENVIRONMENT"
fi

VENV_PYTHON="$VIRTUAL_ENVIRONMENT/bin/python"

step "Updating Python packaging tools"
"$VENV_PYTHON" -m pip install \
  --upgrade \
  pip \
  setuptools \
  wheel

step "Installing Mantha Ray"

INSTALL_TARGET="$("$VENV_PYTHON" - <<'PY'
from pathlib import Path
import tomllib

payload = tomllib.loads(
    Path("pyproject.toml").read_text(encoding="utf-8")
)
optional = (
    payload
    .get("project", {})
    .get("optional-dependencies", {})
)
preferred = [
    name
    for name in ("all", "web", "desktop", "gui")
    if name in optional
]

if preferred:
    print(".[" + ",".join(preferred) + "]")
else:
    print(".")
PY
)"

printf 'Installing editable target: %s\n' "$INSTALL_TARGET"
"$VENV_PYTHON" -m pip install \
  --editable \
  "$INSTALL_TARGET"

if [[ "$build_frontend" == true ]]; then
  step "Building the web interface"
  (
    cd -- "$FRONTEND_DIRECTORY"
    npm ci
    npm run build
  )
else
  step "Using the bundled web interface"
  printf 'Pass --build-frontend after changing files under frontend/.\n'
fi

step "Building the analysis container"
docker build \
  --pull \
  --build-arg "CLAMAV_DB_REFRESH=$(date -u +%Y-%m-%d)" \
  --file "$PROJECT_ROOT/Containerfile" \
  --tag "$IMAGE_NAME" \
  "$PROJECT_ROOT"

step "Verifying the analysis container"
if ! docker run \
  --rm \
  --network none \
  --entrypoint python3 \
  "$IMAGE_NAME" \
  -c '
import inspect
import static_triage.cli as cli

source = inspect.getsource(cli)
raise SystemExit(
    0 if "--progress-jsonl" in source else 1
)
'; then
  printf '%s\n' \
    'The image built, but its scanner is missing --progress-jsonl.' \
    'Confirm that Containerfile copied the current source tree.' \
    >&2
  exit 1
fi

clamav_version="$(
  docker run \
    --rm \
    --network none \
    --entrypoint clamscan \
    "$IMAGE_NAME" \
    --version
)"

step "Setup complete"
printf '%s\n' \
  "Analysis image: $IMAGE_NAME" \
  "ClamAV engine/signatures: $clamav_version" \
  'Signatures expire after 7 days. Run this setup again to refresh them.' \
  '' \
  'Launch Mantha Ray with:' \
  '' \
  '  ./mantha-ray.sh'