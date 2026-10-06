"""Final scanner response parsing and safe host-path reconstruction."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .command import HostScanError


CASE_ID_PATTERN = re.compile(
    r"^case-\d{8}T\d{6}Z-[0-9a-f]{8}$"
)


@dataclass(frozen=True, slots=True)
class DockerScanResult:
    """Host paths derived from a successful scanner response."""

    case_id: str
    status: str
    case_directory: Path
    report_path: Path
    output: str


def parse_scan_output(
    stdout: str,
    stderr: str,
    results_directory: Path,
) -> DockerScanResult:
    """Parse scanner JSON without trusting returned paths."""

    response: dict[str, object] | None = None

    for line in reversed(
        stdout.splitlines()
    ):
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue

        if (
            isinstance(candidate, dict)
            and "ok" in candidate
        ):
            response = candidate
            break

    if response is None:
        detail = (
            stderr.strip()
            or stdout.strip()
        )

        if len(detail) > 500:
            detail = detail[-500:]

        message = (
            "The scanner did not return a valid result."
        )

        if detail:
            message = f"{message} {detail}"

        raise HostScanError(message)

    if response.get("ok") is not True:
        error = response.get("error")

        raise HostScanError(
            str(error)
            if error
            else "The scanner reported a failure."
        )

    case_id = response.get("case_id")
    status = response.get("status")

    if (
        not isinstance(case_id, str)
        or not CASE_ID_PATTERN.fullmatch(
            case_id
        )
    ):
        raise HostScanError(
            "The scanner returned an invalid case ID."
        )

    if (
        not isinstance(status, str)
        or not status
    ):
        raise HostScanError(
            "The scanner returned an invalid status."
        )

    case_directory = (
        results_directory / case_id
    )

    report_path = (
        case_directory / "report.md"
    )

    if not report_path.is_file():
        raise HostScanError(
            "The scan finished, but its Markdown "
            "report is missing."
        )

    combined = stdout

    if stderr:
        combined = (
            f"{stdout.rstrip()}\n"
            f"{stderr.rstrip()}\n"
        )

    return DockerScanResult(
        case_id=case_id,
        status=status,
        case_directory=case_directory,
        report_path=report_path,
        output=combined,
    )