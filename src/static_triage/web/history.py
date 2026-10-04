"""Saved-case discovery, summaries, and loading for the history sidebar."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..host_scan import HostScanError
from .artifacts import load_case_artifacts
from .metadata import metadata_string, read_session_metadata
from .validation import (
    CASE_ID_PATTERN,
    case_created_at,
    read_bounded_text,
    resolve_case_directory,
    resolve_history_root,
    
)


MAX_HISTORY_INDEX_BYTES = 512 * 1024
MAX_HISTORY_CASES = 200


def list_cases(
    results_directory: str,
) -> dict[str, Any]:
    """List bounded summaries for valid saved cases."""

    requested_root = Path(
        results_directory
    ).expanduser()

    if not requested_root.exists():
        return {
            "cases": [],
            "truncated": False,
        }

    root = resolve_history_root(
        results_directory
    )

    try:
        candidates = sorted(
            (
                entry
                for entry in root.iterdir()
                if (
                    CASE_ID_PATTERN.fullmatch(
                        entry.name
                    )
                    is not None
                    and not entry.is_symlink()
                    and entry.is_dir()
                )
            ),
            key=lambda entry: entry.name,
            reverse=True,
        )
    except OSError as exc:
        raise HostScanError(
            "Saved cases could not be listed."
        ) from exc

    summaries: list[dict[str, Any]] = []

    for case_directory in candidates[
        :MAX_HISTORY_CASES
    ]:
        try:
            summaries.append(
                case_summary(
                    root,
                    case_directory.name,
                )
            )
        except (
            HostScanError,
            OSError,
            json.JSONDecodeError,
        ):
            # Ignore incomplete or user-created directories;
            # they are not trustworthy scan history.
            continue

    return {
        "cases": summaries,
        "truncated": (
            len(candidates) > MAX_HISTORY_CASES
        ),
    }


def case_summary(
    root: Path,
    case_id: str,
) -> dict[str, Any]:
    case_directory = resolve_case_directory(
        root,
        case_id,
    )
    metadata = read_session_metadata(
        case_directory
    )
    metadata_case_id = metadata.get("case_id")

    if (
        metadata_case_id is not None
        and metadata_case_id != case_id
    ):
        raise HostScanError(
            "The saved session case ID is invalid."
        )

    for required_name in (
        "report.json",
        "report.md",
    ):
        required_path = (
            case_directory / required_name
        )

        if (
            required_path.is_symlink()
            or not required_path.is_file()
        ):
            raise HostScanError(
                "The saved case is incomplete."
            )

    source_directory = metadata_string(
        metadata,
        "source_directory",
        "",
        max_length=4096,
    )
    created_at = metadata_string(
        metadata,
        "created_at",
        case_created_at(case_id),
    )
    status_value = metadata.get("status")

    if not isinstance(status_value, str):
        report_path = (
            case_directory / "report.json"
        )
        report = json.loads(
            read_bounded_text(
                report_path,
                MAX_HISTORY_INDEX_BYTES,
            )
        )

        if not isinstance(report, dict):
            raise HostScanError(
                "The saved report is invalid."
            )

        status_value = report.get("status")

    if (
        not isinstance(status_value, str)
        or not status_value
        or len(status_value) > 128
    ):
        raise HostScanError(
            "The saved report status is invalid."
        )

    label = (
        Path(source_directory).name
        if source_directory
        else case_id
    )

    return {
        "case_id": case_id,
        "status": status_value,
        "created_at": created_at,
        "source_directory": (
            source_directory or None
        ),
        "label": label,
    }


def load_case_result(
    case_directory: Path,
    case_id: str,
) -> dict[str, Any]:
    report_json_path = (
        case_directory / "report.json"
    )
    report_markdown_path = (
        case_directory / "report.md"
    )
    report = json.loads(
        read_bounded_text(report_json_path)
    )

    if not isinstance(report, dict):
        raise HostScanError(
            "The saved JSON report is invalid."
        )

    reported_case_id = report.get("case_id")

    if reported_case_id != case_id:
        raise HostScanError(
            "The saved report case ID does not match its directory."
        )

    status_value = report.get("status")

    if (
        not isinstance(status_value, str)
        or not status_value
        or len(status_value) > 128
    ):
        raise HostScanError(
            "The saved report status is invalid."
        )

    return {
        "case_id": case_id,
        "status": status_value,
        "case_directory": str(case_directory),
        "report_path": str(report_markdown_path),
        "report": report,
        "report_markdown": read_bounded_text(
            report_markdown_path
        ),
        "artifacts": load_case_artifacts(
            case_directory
        ),
    }