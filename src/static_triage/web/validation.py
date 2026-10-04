"""Path, case-ID, and bounded-read validation for the web service.

These checks guard every filesystem read the browser can trigger. Keep
symlink rejection, root containment, and read bounds intact.
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime
from pathlib import Path

from ..host_scan import HostScanError


MAX_REPORT_BYTES = 8 * 1024 * 1024
CASE_ID_PATTERN = re.compile(
    r"^case-(\d{8}T\d{6}Z)-[0-9a-f]{8}$"
)


def paths_overlap(first: Path, second: Path) -> bool:
    return (
        first == second
        or first.is_relative_to(second)
        or second.is_relative_to(first)
    )


def read_bounded_text(
    path: Path,
    max_bytes: int = MAX_REPORT_BYTES,
) -> str:
    if path.is_symlink() or not path.is_file():
        raise HostScanError(
            f"Required file '{path.name}' is unavailable."
        )

    if path.stat().st_size > max_bytes:
        raise HostScanError(
            f"File '{path.name}' exceeds the web limit."
        )

    return path.read_text(
        encoding="utf-8",
        errors="replace",
    )


def case_created_at(case_id: str) -> str:
    match = CASE_ID_PATTERN.fullmatch(case_id)

    if match is None:
        raise HostScanError(
            "The requested case ID is invalid."
        )

    try:
        created = datetime.strptime(
            match.group(1),
            "%Y%m%dT%H%M%SZ",
        ).replace(tzinfo=UTC)
    except ValueError as exc:
        raise HostScanError(
            "The requested case ID is invalid."
        ) from exc

    return created.isoformat()


def resolve_history_root(
    results_directory: str,
) -> Path:
    try:
        root = Path(
            results_directory
        ).expanduser().resolve(strict=True)
    except OSError as exc:
        raise HostScanError(
            "The results directory is unavailable."
        ) from exc

    if not root.is_dir():
        raise HostScanError(
            "The results path must be a directory."
        )

    if not os.access(root, os.R_OK | os.X_OK):
        raise HostScanError(
            "The results directory is not readable."
        )

    return root


def resolve_case_directory(
    root: Path,
    case_id: str,
) -> Path:
    case_created_at(case_id)
    candidate = root / case_id

    if candidate.is_symlink():
        raise HostScanError(
            "Symbolic-link case directories are not allowed."
        )

    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise HostScanError(
            "The requested case directory is unavailable."
        ) from exc

    if resolved.parent != root or not resolved.is_dir():
        raise HostScanError(
            "The requested case directory is unavailable."
        )

    return resolved