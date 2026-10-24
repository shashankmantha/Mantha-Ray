from __future__ import annotations

import signal
import threading

# Sent by the host (or scripts/stop-scan.sh) to ask a running scan to stop
# starting new work, end what is running, and still write its report.
# SIGTERM/SIGKILL (docker stop) remain the hard cancel that saves nothing.
STOP_SIGNAL = signal.SIGUSR1
STOPPED_MESSAGE = "the scan was stopped by the user"

_requested = threading.Event()


def request() -> None:
    _requested.set()


def requested() -> bool:
    return _requested.is_set()


def reset() -> None:
    _requested.clear()


def install() -> None:
    # Only the main thread may install signal handlers; the handler just
    # sets a flag, which every analyzer checks between and during files.
    signal.signal(STOP_SIGNAL, lambda signum, frame: _requested.set())
