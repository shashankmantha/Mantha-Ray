"""Bounded, sanitized loading of a case's files.jsonl inventory."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from ..host_scan import HostScanError
from .validation import read_bounded_text


MAX_FILES_JSONL_BYTES = 32 * 1024 * 1024
MAX_ARTIFACT_LINE_BYTES = 64 * 1024
MAX_ARTIFACTS = 25_000
MAX_ARTIFACT_PATH_LENGTH = 4096


def _optional_artifact_string(
    item: dict[str, Any],
    name: str,
    *,
    max_length: int = 512,
) -> str | None:
    value = item.get(name)

    if (
        isinstance(value, str)
        and len(value) <= max_length
    ):
        return value

    return None


def _validated_artifact_path(
    value: object,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_ARTIFACT_PATH_LENGTH
    ):
        raise HostScanError(
            "The saved artifact inventory contains "
            "an invalid relative path."
        )

    path = PurePosixPath(value)

    if (
        path.is_absolute()
        or any(
            part in {"", ".", ".."}
            for part in path.parts
        )
    ):
        raise HostScanError(
            "The saved artifact inventory contains "
            "an unsafe relative path."
        )

    return path.as_posix()


def load_case_artifacts(
    case_directory: Path,
) -> list[dict[str, Any]]:
    """Load a bounded and sanitized files.jsonl inventory."""

    inventory_path = case_directory / "files.jsonl"

    if not inventory_path.exists():
        # Older or manually-created test cases may not have
        # an inventory file.
        return []

    contents = read_bounded_text(
        inventory_path,
        MAX_FILES_JSONL_BYTES,
    )
    artifacts: list[dict[str, Any]] = []

    for line_number, raw_line in enumerate(
        contents.splitlines(),
        start=1,
    ):
        if not raw_line.strip():
            continue

        if (
            len(raw_line.encode("utf-8"))
            > MAX_ARTIFACT_LINE_BYTES
        ):
            raise HostScanError(
                "An artifact inventory entry exceeds "
                "the web limit."
            )

        if len(artifacts) >= MAX_ARTIFACTS:
            raise HostScanError(
                "The artifact inventory exceeds "
                "the web file limit."
            )

        try:
            item = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise HostScanError(
                "The saved artifact inventory contains "
                f"invalid JSON on line {line_number}."
            ) from exc

        if not isinstance(item, dict):
            raise HostScanError(
                "The saved artifact inventory contains "
                f"an invalid entry on line {line_number}."
            )

        relative_path = _validated_artifact_path(
            item.get("relative_path")
        )

        size_value = item.get("size_bytes")
        size_bytes = (
            size_value
            if (
                isinstance(size_value, int)
                and not isinstance(size_value, bool)
                and size_value >= 0
            )
            else None
        )

        sha256 = _optional_artifact_string(
            item,
            "sha256",
            max_length=64,
        )

        if (
            sha256 is not None
            and re.fullmatch(
                r"[0-9a-fA-F]{64}",
                sha256,
            )
            is None
        ):
            sha256 = None

        evidence = item.get("evidence")
        review_flags = (
            len(evidence)
            if isinstance(evidence, list)
            else 0
        )

        artifacts.append(
            {
                "relative_path": relative_path,
                "kind": (
                    _optional_artifact_string(
                        item,
                        "kind",
                        max_length=64,
                    )
                    or "unknown"
                ),
                "detected_type": (
                    _optional_artifact_string(
                        item,
                        "detected_type",
                        max_length=256,
                    )
                ),
                "routing_class": (
                    _optional_artifact_string(
                        item,
                        "routing_class",
                        max_length=64,
                    )
                ),
                "state": (
                    _optional_artifact_string(
                        item,
                        "state",
                        max_length=64,
                    )
                ),
                "mode": (
                    _optional_artifact_string(
                        item,
                        "mode",
                        max_length=32,
                    )
                ),
                "size_bytes": size_bytes,
                "sha256": (
                    sha256.lower()
                    if sha256 is not None
                    else None
                ),
                "review_flags": review_flags,
                "error": (
                    _optional_artifact_string(
                        item,
                        "error",
                        max_length=1024,
                    )
                ),
            }
        )

    return artifacts