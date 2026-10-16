

from __future__ import annotations

import os
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ProgressCallback = Callable[[str, str, str], None]

TERMINAL_STAGE_STATUSES = frozenset(
    {"completed", "incomplete", "unavailable", "error"}
)

_MIB = 1024**2

# Allow small differences, e.g. tmpfs sizes rounded to pages.
_TMP_TOLERANCE_BYTES = _MIB


def _utc_iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).isoformat()


class StageTimer:
    """Record when each analysis stage starts and finishes.

    It observes the same progress events the live UI receives, so
    timings follow the stage states users already see. Durations use a
    monotonic clock; start and end times are UTC wall-clock.
    """

    def __init__(
        self,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self._clock = clock
        self._wall_clock = wall_clock
        self._stages: dict[str, dict[str, Any]] = {}
        self._started: dict[str, float] = {}

    def wrap(
        self,
        callback: ProgressCallback | None,
    ) -> ProgressCallback:
        """Return a callback that records timing, then forwards."""

        def observe(stage: str, status: str, message: str) -> None:
            self.observe(stage, status)
            if callback is not None:
                callback(stage, status, message)

        return observe

    def observe(self, stage: str, status: str) -> None:
        if status == "running":
            self._started[stage] = self._clock()
            self._stages[stage] = {
                "status": "running",
                "started_at": _utc_iso(self._wall_clock()),
                "completed_at": None,
                "duration_seconds": None,
            }
            return

        if status not in TERMINAL_STAGE_STATUSES:
            return

        record = self._stages.setdefault(
            stage,
            {
                "status": status,
                "started_at": None,
                "completed_at": None,
                "duration_seconds": None,
            },
        )
        record["status"] = status
        record["completed_at"] = _utc_iso(self._wall_clock())
        began = self._started.pop(stage, None)
        if began is not None:
            record["duration_seconds"] = round(self._clock() - began, 3)

    def to_dict(self) -> dict[str, dict[str, Any]]:
        """Return a copy of the timings recorded so far."""

        return {
            stage: dict(record)
            for stage, record in self._stages.items()
        }


def _read_small(path: Path) -> str | None:
    try:
        with path.open("r", encoding="ascii", errors="replace") as handle:
            return handle.read(256).strip()
    except OSError:
        return None


def _positive_int(text: str) -> int | None:
    try:
        value = int(text)
    except ValueError:
        return None
    return value if value > 0 else None


def read_container_limits(
    cgroup_root: Path = Path("/sys/fs/cgroup"),
    tmp_path: Path = Path("/tmp"),
) -> dict[str, Any]:
    """Read the limits actually applied to this process.

    Uses cgroup v2 files. ``None`` means unlimited or unknown; outside
    a container these are usually the host's (absent) limits.
    """

    observed: dict[str, Any] = {
        "source": "cgroup-v2",
        "memory_bytes": None,
        "cpus": None,
        "pids": None,
        "tmp_bytes": None,
    }

    memory = _read_small(cgroup_root / "memory.max")
    cpu = _read_small(cgroup_root / "cpu.max")
    pids = _read_small(cgroup_root / "pids.max")

    if memory is None and cpu is None and pids is None:
        observed["source"] = "unavailable"

    if memory and memory != "max":
        observed["memory_bytes"] = _positive_int(memory)

    if cpu:
        parts = cpu.split()
        if len(parts) == 2 and parts[0] != "max":
            quota = _positive_int(parts[0])
            period = _positive_int(parts[1])
            if quota and period:
                observed["cpus"] = round(quota / period, 2)

    if pids and pids != "max":
        observed["pids"] = _positive_int(pids)

    try:
        stats = os.statvfs(tmp_path)
        observed["tmp_bytes"] = stats.f_blocks * stats.f_frsize
    except OSError:
        pass

    return observed


def compare_limits(
    values: dict[str, Any],
    observed: dict[str, Any],
) -> list[str]:
    """List profile settings the container is not enforcing."""

    expected = {
        "memory_bytes": values["memory_mib"] * _MIB,
        "cpus": values["cpus"],
        "pids": values["pids_limit"],
    }
    mismatches = [
        name
        for name, wanted in expected.items()
        if observed.get(name) is None
        or abs(observed[name] - wanted) > 1e-6
    ]
    tmp = observed.get("tmp_bytes")
    if tmp is None or abs(tmp - values["tmp_mib"] * _MIB) > _TMP_TOLERANCE_BYTES:
        mismatches.append("tmp_bytes")
    return mismatches


def resources_record(
    profile: dict[str, Any],
    observed: dict[str, Any],
) -> dict[str, Any]:
    """Build the report's ``resources`` block."""

    values = profile["values"]
    mismatches = compare_limits(values, observed)
    return {
        "profile": profile["name"],
        "base": profile["base"],
        "values": values,
        "changed": profile["changed"],
        "observed": observed,
        "enforced": not mismatches,
        "not_enforced": mismatches,
    }