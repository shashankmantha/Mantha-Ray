#!/usr/bin/env bash
# Usage: ./scripts/stop-scan.sh [--discard] [CONTAINER_NAME]
# Stops a running Mantha Ray scan from the terminal, e.g. when the window
# is closed or has crashed. By default the scan ends its analyses and still
# writes a report of the work finished so far. --discard ends it at once
# and saves nothing.
set -euo pipefail

ENGINE="${MANTHA_RAY_ENGINE:-docker}"
GRACE_SECONDS=180
discard=false
name=""

for arg in "$@"; do
  case "$arg" in
    --discard) discard=true ;;
    -h|--help)
      sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    -*) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
    *) name="$arg" ;;
  esac
done

mapfile -t running < <(
  "$ENGINE" ps --filter "name=^static-triage-" --format '{{.Names}}'
)

if [[ -n "$name" ]]; then
  found=false
  for candidate in "${running[@]}"; do
    [[ "$candidate" == "$name" ]] && found=true
  done
  if ! $found; then
    echo "No running Mantha Ray scan is named $name." >&2
    exit 1
  fi
elif ((${#running[@]} == 0)); then
  echo "No Mantha Ray scan is running."
  exit 0
elif ((${#running[@]} > 1)); then
  echo "More than one scan is running; name the one to stop:" >&2
  printf '  %s\n' "${running[@]}" >&2
  exit 2
else
  name="${running[0]}"
fi

if $discard; then
  word="discard"
  echo "This ends scan $name immediately. Nothing it has done is saved."
else
  word="stop"
  echo "This stops scan $name. Analyses in progress are ended and a"
  echo "report of the work finished so far is saved. It can't be resumed."
fi
read -r -p "Type '$word' to confirm, anything else to keep scanning: " reply
if [[ "$reply" != "$word" ]]; then
  echo "Kept scanning."
  exit 1
fi

if $discard; then
  "$ENGINE" stop --time 5 "$name" >/dev/null
  echo "Scan $name was ended without a report."
  exit 0
fi

"$ENGINE" kill --signal USR1 "$name" >/dev/null
echo "Stop requested. Waiting for the report to be written..."
for ((waited = 0; waited < GRACE_SECONDS; waited += 2)); do
  if ! "$ENGINE" ps --filter "name=^${name}\$" --format '{{.Names}}' | grep -q .; then
    echo "Scan stopped and its report was saved. See it with ./scripts/summary.sh"
    exit 0
  fi
  sleep 2
done
echo "The scan is still running after ${GRACE_SECONDS} s." >&2
echo "To end it without a report: ./scripts/stop-scan.sh --discard $name" >&2
exit 1
