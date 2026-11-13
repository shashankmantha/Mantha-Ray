#!/usr/bin/env bash
# Usage: ./scripts/reference-check.sh [CASE_FOLDER | RESULTS_FOLDER] [--full] [--check FILE]
# Lists the executables a scan inventoried, and can say which of them match a
# list of published vendor or crack-component builds.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON="python3"
fi

PYTHONPATH="$ROOT/src" exec "$PYTHON" -m static_triage.reference_check "$@"
