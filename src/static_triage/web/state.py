"""Scan state, lifecycle constants, and analyzer-stage helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


ACTIVE_STATES = {
    "queued",
    "preflight",
    "running",
    "cancelling",
}
TERMINAL_STATES = {
    "completed",
    "failed",
    "cancelled",
}

SCAN_STAGE_NAMES = (
    "inventory",
    "clamav",
    "capa",
    "floss",
    "report",
)

SCAN_STAGE_STATUSES = frozenset(
    {
        "waiting",
        "running",
        "completed",
        "incomplete",
        "unavailable",
        "error",
        "cancelled",
    }
)


def waiting_stages() -> dict[str, str]:
    return {
        stage: "waiting"
        for stage in SCAN_STAGE_NAMES
    }


def stages_from_report(
    report: dict[str, Any],
) -> dict[str, str]:
    """Derive final stage health from an authoritative report."""

    stages = waiting_stages()
    summary = report.get("summary")

    if isinstance(summary, dict):
        inventory_complete = (
            summary.get("errors", 0) == 0
            and summary.get("limit_exceeded", 0) == 0
        )
        stages["inventory"] = (
            "completed"
            if inventory_complete
            else "incomplete"
        )

    analyzers = report.get("analyzers")

    if isinstance(analyzers, dict):
        for name in ("clamav", "capa", "floss"):
            analyzer = analyzers.get(name)

            if not isinstance(analyzer, dict):
                continue

            analyzer_status = analyzer.get("status")

            if analyzer_status == "not_run":
                stages[name] = "unavailable"
            elif analyzer_status == "error":
                stages[name] = "error"
            elif analyzer.get("complete") is True:
                stages[name] = "completed"
            else:
                stages[name] = "incomplete"

    stages["report"] = "completed"
    return stages

def now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class WebScanState:
    """Internal state for one browser-initiated scan."""

    scan_id: str
    source_directory: str
    results_directory: str
    state: str = "queued"
    message: str = "Scan queued."
    created_at: str = field(default_factory=now)
    updated_at: str = field(default_factory=now)
    events: list[dict[str, str]] = field(
        default_factory=list
    )
    stages: dict[str, str] = field(
        default_factory=waiting_stages
    )
    result: dict[str, Any] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)