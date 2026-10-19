#!/usr/bin/env bash
# Usage: ./scripts/test.sh [--python-only] [-v]
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then PYTHON="python3"; fi

PYTHON_ONLY=0
VERBOSE=""
for arg in "$@"; do
  case "$arg" in
    --python-only) PYTHON_ONLY=1 ;;
    -v) VERBOSE="-v" ;;
    -h|--help)
      echo "usage: test.sh [--python-only] [-v]"
      echo "Runs the Python tests, checks shell script syntax and"
      echo "type-checks the frontend. Exits non-zero if anything fails."
      exit 0 ;;
    *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
  esac
done

cd "$ROOT"
results=()
failed=0

record() {
  if [[ "$2" -eq 0 ]]; then
    results+=("PASS  $1")
  else
    results+=("FAIL  $1")
    failed=1
  fi
}

echo "== Python tests ($PYTHON)"
PYTHONPATH="$ROOT/src" "$PYTHON" -m unittest discover -s tests -p 'test_*.py' $VERBOSE
record "Python tests" $?

if [[ "$PYTHON_ONLY" -eq 0 ]]; then
  echo
  echo "== Shell script syntax"
  status=0
  for script in scripts/*.sh; do
    bash -n "$script" || { echo "syntax error: $script"; status=1; }
  done
  [[ "$status" -eq 0 ]] && echo "all scripts OK"
  record "Shell script syntax" $status

  echo
  echo "== Frontend type check"
  if ! command -v npm >/dev/null 2>&1; then
    echo "npm not found"
    results+=("SKIP  Frontend type check (npm not installed)")
  elif [[ ! -d frontend/node_modules ]]; then
    echo "frontend/node_modules missing; run ./scripts/setup.sh first"
    results+=("SKIP  Frontend type check (run ./scripts/setup.sh)")
  else
    (cd frontend && npm run --silent typecheck)
    status=$?
    [[ "$status" -eq 0 ]] && echo "types OK"
    record "Frontend type check" $status
  fi
fi

echo
echo "== Summary"
printf '  %s\n' "${results[@]}"
exit "$failed"