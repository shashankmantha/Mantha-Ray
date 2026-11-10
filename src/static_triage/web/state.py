"""Scan state, lifecycle constants, and analyzer-stage helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


ACTIVE_STATES = {
    "queued",
    "preflight",
    "running",
    "stopping",
    "cancelling",
}
# The activity log keeps only the newest messages, so a long scan of a big
# folder can't grow the app's memory (or every status reply) without limit.
MAX_EVENTS = 1000

TERMINAL_STATES = {
    "completed",
    "failed",
    "cancelled",
}

SCAN_STAGE_NAMES = (
    "inventory",
    "clamav",
    "yara",
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
        for name in ("clamav", "yara", "capa", "floss"):
            analyzer = analyzers.get(name)

            if not isinstance(analyzer, dict):
                if name == "yara":
                    stages[name] = "unavailable"  # older case
                continue

            analyzer_status = analyzer.get("status")

            if analyzer_status in ("not_run", "unavailable"):
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
    events: list[dict[str, Any]] = field(
        default_factory=list
    )
    # Messages ever added, including ones dropped from the log. Each event's
    # "seq" is its number, so the app can ask for only the new ones.
    event_count: int = 0
    # Planned file order per analyzer stage, with each file's status.
    queues: dict[str, dict[str, Any]] = field(
        default_factory=dict
    )
    # Bumped whenever a queue changes, so the app can skip resending them.
    queues_version: int = 0
    stages: dict[str, str] = field(
        default_factory=waiting_stages
    )
    result: dict[str, Any] | None = None
    error: str | None = None
    # Summary of the resolved resource profile for live display. The
    # saved report's "resources" block is authoritative afterwards.
    resource_profile: dict[str, Any] | None = None

    def add_event(self, time: str, message: str) -> None:
        self.event_count += 1
        self.events.append(
            {"seq": self.event_count, "time": time, "message": message}
        )
        if len(self.events) > MAX_EVENTS:
            del self.events[: len(self.events) - MAX_EVENTS]

    def to_dict(
        self,
        since: int | None = None,
        queues_since: int | None = None,
    ) -> dict[str, Any]:
        """The scan's state; with since, only the events after that number;
        with queues_since, queues only if they changed after that version."""

        unchanged = queues_since is not None and queues_since == self.queues_version
        if unchanged:
            self.queues, saved = {}, self.queues
            try:
                data = asdict(self)
            finally:
                self.queues = saved
            data["queues"] = None
        else:
            data = asdict(self)
        if since is not None:
            data["events"] = [
                event for event in data["events"] if event["seq"] > since
            ]
        return data