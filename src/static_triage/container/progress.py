"""Bounded parsing of JSONL progress events from the scanner."""

from __future__ import annotations

import json


PROGRESS_STAGES = frozenset(
    {
        "inventory",
        "clamav",
        "capa",
        "floss",
        "report",
    }
)


PROGRESS_STATUSES = frozenset(
    {
        "waiting",
        "running",
        "completed",
        "incomplete",
        "unavailable",
        "error",
    }
)


def parse_progress_event(
    line: str,
) -> tuple[str, str, str] | None:
    """Parse one bounded scanner progress event."""

    if len(line) > 8192:
        return None

    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None

    if payload.get("type") != "progress":
        return None

    stage = payload.get("stage")
    status = payload.get("status")
    message = payload.get("message")

    if (
        not isinstance(stage, str)
        or stage not in PROGRESS_STAGES
        or not isinstance(status, str)
        or status not in PROGRESS_STATUSES
        or not isinstance(message, str)
        or not message
        or len(message) > 4096
    ):
        return None

    return stage, status, message