#!/usr/bin/env bash

set -u

SCRIPT_DIRECTORY="$(
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
  pwd
)"
PROJECT_ROOT="$(
  cd -- "$SCRIPT_DIRECTORY/.."
  pwd
)"

check_frontend=false
failure_count=0

usage() {
  cat <<'EOF'
Usage: ./scripts/check-requirements.sh [--frontend]

Checks the normal Mantha Ray runtime requirements.

Options:
  --frontend  Also require Node.js and npm for rebuilding the frontend.
  -h, --help  Show this help message.
EOF
}

while (($# > 0)); do
  case "$1" in
    --frontend)
      check_frontend=true
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

pass() {
  printf '[ok]   %s\n' "$1"
}

fail() {
  printf '[fail] %s\n' "$1" >&2
  failure_count=$((failure_count + 1))
}

note() {
  printf '[info] %s\n' "$1"
}

check_command() {
  local command_name="$1"
  local display_name="$2"

  if command -v "$command_name" >/dev/null 2>&1; then
    pass "$display_name: $(command -v "$command_name")"
  else
    fail "$display_name is not installed"
  fi
}

print_install_hints() {
  local distribution_id="unknown"
  local distribution_like=""

  if [[ -r /etc/os-release ]]; then
    # Values in this system-owned file identify the distribution.
    # shellcheck disable=SC1091
    source /etc/os-release
    distribution_id="${ID:-unknown}"
    distribution_like="${ID_LIKE:-}"
  fi

  printf '\nSuggested runtime prerequisite installation:\n\n'

  case "$distribution_id $distribution_like" in
    *nobara*|*fedora*|*rhel*)
      printf '%s\n' \
        '  sudo dnf install git python3 python3-pip python3-tkinter moby-engine docker-cli docker-buildx' \
        '  sudo systemctl enable --now docker'
      ;;
    *ubuntu*|*debian*)
      printf '%s\n' \
        '  sudo apt update' \
        '  sudo apt install git python3 python3-venv python3-pip python3-tk docker.io docker-buildx-plugin' \
        '  sudo systemctl enable --now docker'
      ;;
    *arch*)
      printf '%s\n' \
        '  sudo pacman -S --needed git python python-pip tk docker docker-buildx' \
        '  sudo systemctl enable --now docker'
      ;;
    *opensuse*|*suse*)
      printf '%s\n' \
        '  sudo zypper install git python3 python3-pip python3-tk docker docker-buildx' \
        '  sudo systemctl enable --now docker'
      ;;
    *)
      printf '%s\n' \
        '  Install Git, Python 3.11+, Python venv and Tk support,' \
        '  Docker Engine, the Docker CLI, and Docker Buildx.'
      ;;
  esac

  if [[ "$check_frontend" == true ]]; then
    printf '%s\n' \
      '' \
      'Frontend development additionally requires:' \
      '' \
      '  Node.js 20.19+, 22.12+, or newer' \
      '  npm'
  fi

  printf '%s\n' \
    '' \
    'If Docker is installed but access is denied:' \
    '' \
    '  sudo usermod -aG docker "$USER"' \
    '' \
    'Sign out and back in after changing Docker group membership.' \
    'Docker group access is effectively equivalent to root access.'
}

printf 'Mantha Ray requirements check\n'
printf 'Project: %s\n\n' "$PROJECT_ROOT"

if [[ "$(uname -s)" == "Linux" ]]; then
  pass "Linux host detected"
else
  fail "Mantha Ray currently requires Linux"
fi

check_command git "Git"
check_command python3 "Python 3"
check_command docker "Docker"

if command -v python3 >/dev/null 2>&1; then
  python_version="$(python3 --version 2>&1)"

  if python3 -c '
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
'; then
    pass "$python_version"
  else
    fail "$python_version detected; Python 3.11+ is required"
  fi

  if python3 -c 'import venv' >/dev/null 2>&1; then
    pass "Python venv support is available"
  else
    fail "Python venv support is unavailable"
  fi

  if python3 -c 'import tkinter' >/dev/null 2>&1; then
    pass "Python Tkinter support is available"
  else
    fail "Python Tkinter support is unavailable"
  fi
fi

if [[ "$check_frontend" == true ]]; then
  check_command node "Node.js"
  check_command npm "npm"

  if command -v node >/dev/null 2>&1; then
    node_version="$(node --version 2>&1)"

    if node -e '
const [major, minor] = process.versions.node
  .split(".")
  .map(Number);
const supported = (
  (major === 20 && minor >= 19)
  || (major === 22 && minor >= 12)
  || major > 22
);
process.exit(supported ? 0 : 1);
'; then
      pass "Node.js $node_version"
    else
      fail "Node.js $node_version detected; use 20.19+, 22.12+, or newer"
    fi
  fi

  if command -v npm >/dev/null 2>&1; then
    pass "npm $(npm --version 2>/dev/null)"
  fi
else
  note "Using bundled frontend assets; Node.js and npm are not required"
fi

if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then
    pass "Docker daemon is running and accessible"
  else
    fail "Docker daemon is unavailable or access was denied"
  fi

  if docker buildx version >/dev/null 2>&1; then
    pass "Docker Buildx is available"
  else
    fail "Docker Buildx is unavailable"
  fi
fi

required_paths=(
  "$PROJECT_ROOT/pyproject.toml"
  "$PROJECT_ROOT/Containerfile"
  "$PROJECT_ROOT/src/static_triage/web_dist/index.html"
)

if [[ "$check_frontend" == true ]]; then
  required_paths+=(
    "$PROJECT_ROOT/frontend/package.json"
    "$PROJECT_ROOT/frontend/package-lock.json"
  )
fi

for required_path in "${required_paths[@]}"; do
  if [[ -f "$required_path" ]]; then
    pass "Found ${required_path#"$PROJECT_ROOT/"}"
  else
    fail "Missing ${required_path#"$PROJECT_ROOT/"}"
  fi
done

printf '\n'

if ((failure_count > 0)); then
  printf '[fail] %s requirement check(s) failed\n' \
    "$failure_count" \
    >&2
  print_install_hints
  exit 1
fi

note "All requested setup requirements are satisfied."