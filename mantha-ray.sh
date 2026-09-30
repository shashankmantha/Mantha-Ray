#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_ROOT="$(
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
  pwd
)"
MANTHA_RAY="$PROJECT_ROOT/.venv/bin/mantha-ray"

if [[ ! -x "$MANTHA_RAY" ]]; then
  printf '%s\n' \
    'Mantha Ray is not installed in this repository.' \
    'Run the setup command first:' \
    '' \
    '  ./scripts/setup.sh' \
    >&2
  exit 1
fi

cd -- "$PROJECT_ROOT"
exec "$MANTHA_RAY" "$@"
