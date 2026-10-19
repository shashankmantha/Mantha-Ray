#!/usr/bin/env bash
# Usage: ./scripts/summary.sh [CASE_FOLDER | RESULTS_FOLDER]
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON="python3"
fi

PYTHONPATH="$ROOT/src" exec "$PYTHON" -m static_triage.case_summary "$@"