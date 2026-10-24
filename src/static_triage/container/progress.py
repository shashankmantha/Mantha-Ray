"""Bounded parsing of JSONL progress events from the scanner."""

from __future__ import annotations

import json


PROGRESS_STAGES = frozenset(
    {
        "inventory",
        "clamav",
        "yara",
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


QUEUE_STAGES = frozenset({"capa", "floss"})
QUEUE_MODES = frozenset({"", "plain strings"})
MAX_QUEUE_TOTAL = 10_000


def parse_queue_event(
    line: str,
) -> tuple[str, int, int, list[dict[str, object]]] | None:
    """Parse one bounded chunk of a stage's planned file order."""

    if len(line) > 8192:
        return None
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict) or payload.get("type") != "queue":
        return None

    stage = payload.get("stage")
    offset = payload.get("offset")
    total = payload.get("total")
    raw_items = payload.get("items")
    if (
        stage not in QUEUE_STAGES
        or not _small_int(total, MAX_QUEUE_TOTAL)
        or not _small_int(offset, total)
        or not isinstance(raw_items, list)
        or offset + len(raw_items) > total
    ):
        return None

    items: list[dict[str, object]] = []
    for raw in raw_items:
        if not isinstance(raw, dict):
            return None
        position = raw.get("position")
        path = raw.get("path")
        size = raw.get("size")
        copies = raw.get("copies")
        mode = raw.get("mode")
        if (
            not _small_int(position, total)
            or position < 1
            or not isinstance(path, str)
            or not path
            or len(path) > 300
            or not isinstance(size, str)
            or len(size) > 32
            or not _small_int(copies, MAX_QUEUE_TOTAL * 100)
            or mode not in QUEUE_MODES
        ):
            return None
        items.append(
            {
                "position": position,
                "path": path,
                "size": size,
                "copies": copies,
                "mode": mode,
            }
        )
    return stage, offset, total, items


def _small_int(value: object, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= maximum
    )
