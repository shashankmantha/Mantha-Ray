"""The web-session.json sidecar: schema, bounded read, and atomic write.

The sidecar stores browser-facing scan metadata next to a case. Reports
remain authoritative; this file is optional and validated on load.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..host_scan import HostScanError
from .validation import read_bounded_text


MAX_SESSION_METADATA_BYTES = 1024 * 1024
MAX_HISTORY_EVENTS = 500
SESSION_METADATA_NAME = "web-session.json"


def metadata_string(
    metadata: dict[str, Any],
    name: str,
    default: str,
    *,
    max_length: int = 128,
) -> str:
    value = metadata.get(name)

    if (
        isinstance(value, str)
        and 0 < len(value) <= max_length
    ):
        return value

    return default


def metadata_events(
    metadata: dict[str, Any],
) -> list[dict[str, str]]:
    raw_events = metadata.get("events")

    if not isinstance(raw_events, list):
        return []

    events: list[dict[str, str]] = []

    for item in raw_events[:MAX_HISTORY_EVENTS]:
        if not isinstance(item, dict):
            continue

        time_value = item.get("time")
        message = item.get("message")

        if (
            isinstance(time_value, str)
            and isinstance(message, str)
            and len(time_value) <= 64
            and len(message) <= 4096
        ):
            events.append(
                {
                    "time": time_value,
                    "message": message,
                }
            )

    return events


def read_session_metadata(
    case_directory: Path,
) -> dict[str, Any]:
    path = case_directory / SESSION_METADATA_NAME

    if not path.exists():
        return {}

    metadata = json.loads(
        read_bounded_text(
            path,
            MAX_SESSION_METADATA_BYTES,
        )
    )

    if not isinstance(metadata, dict):
        raise HostScanError(
            "The saved session metadata is invalid."
        )

    if metadata.get("schema_version") != 1:
        raise HostScanError(
            "The saved session metadata version is unsupported."
        )

    return metadata


def persist_session_metadata(
    state: dict[str, Any],
) -> None:
    result = state.get("result")

    if not isinstance(result, dict):
        return

    case_value = result.get("case_directory")
    status_value = result.get("status")

    if (
        not isinstance(case_value, str)
        or not isinstance(status_value, str)
    ):
        return

    case_directory = Path(case_value)
    metadata_path = (
        case_directory / SESSION_METADATA_NAME
    )
    temporary_path = (
        case_directory
        / f".{SESSION_METADATA_NAME}.{uuid4().hex}.tmp"
    )

    metadata = {
        "schema_version": 1,
        "case_id": result.get("case_id"),
        "status": status_value,
        "source_directory": state.get(
            "source_directory"
        ),
        "created_at": state.get("created_at"),
        "updated_at": state.get("updated_at"),
        "events": state.get("events", [])[
            -MAX_HISTORY_EVENTS:
        ],
        "stages": state.get("stages", {}),
    }

    temporary_path.write_text(
        json.dumps(
            metadata,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    temporary_path.replace(metadata_path)