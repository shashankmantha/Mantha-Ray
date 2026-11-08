#!/usr/bin/env bash

set -Eeuo pipefail

# Follow the link setup.sh puts in ~/.local/bin back to the repository.
PROJECT_ROOT="$(
  cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")"
  pwd
)"
MANTHA_RAY="$PROJECT_ROOT/.venv/bin/mantha-ray"

if [[ ! -x "$MANTHA_RAY" ]]; then
  printf '%s\n' \
    "Mantha Ray is not installed in $PROJECT_ROOT." \
    'Run the setup command there first:' \
    '' \
    '  ./scripts/setup.sh' \
    >&2
  exit 1
fi

# Opening the window runs from the repository; commands such as
# `mantha-ray packs add my_rules.yar` keep the current folder so relative
# paths still point where the user meant.
if [[ $# -eq 0 ]]; then
  cd -- "$PROJECT_ROOT"
fi

exec "$MANTHA_RAY" "$@"
