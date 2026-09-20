"""FLOSS adapter for bounded string deobfuscation."""

from __future__ import annotations

import json
import os
import time 

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .runner import CommandResult, run_command

from .models import (
    EntryKind,
    EntryState,
    InventoryEntry,
    RoutingClass,
)


class FlossStatus(str, Enum):
    """Normalized FLOSS outcomes."""

    COMPLETED = "completed"
    ERROR = "error"
    TIMED_OUT = "timed_out"

class FlossBatchStatus(str, Enum):
    """Normalized outcome of the complete FLOSS stage."""

    COMPLETED = "completed"
    PARTIAL = "partial"


@dataclass(frozen=True, slots=True)
class FlossString:
    """One normalized string extracted by FLOSS."""

    kind: str
    value: str
    encoding: str | None
    truncated: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "encoding": self.encoding,
            "truncated": self.truncated,
        }


@dataclass(frozen=True, slots=True)
class FlossResult:
    """Normalized result from one FLOSS analysis."""

    status: FlossStatus
    complete: bool
    relative_path: str
    return_code: int
    strings: tuple[FlossString, ...]
    total_strings: int
    strings_truncated: bool
    timed_out: bool
    output_truncated: bool
    duration_seconds: float
    stdout: str
    stderr: str
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "complete": self.complete,
            "relative_path": self.relative_path,
            "return_code": self.return_code,
            "extracted_string_count": len(
                self.strings
            ),
            "total_string_count": self.total_strings,
            "strings_truncated": (
                self.strings_truncated
            ),
            "strings": [
                item.to_dict()
                for item in self.strings
            ],
            "timed_out": self.timed_out,
            "output_truncated": (
                self.output_truncated
            ),
            "duration_seconds": (
                self.duration_seconds
            ),
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class FlossBatchResult:
    """Normalized result from the complete FLOSS stage."""

    status: FlossBatchStatus
    complete: bool
    eligible_files: int
    attempted_files: int
    skipped_due_to_limit: int
    skipped_due_to_timeout: int
    results: tuple[FlossResult, ...]
    duration_seconds: float
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "complete": self.complete,
            "eligible_files": self.eligible_files,
            "attempted_files": self.attempted_files,
            "skipped_due_to_limit": (
                self.skipped_due_to_limit
            ),
            "skipped_due_to_timeout": (
                self.skipped_due_to_timeout
            ),
            "extracted_string_count": sum(
                len(result.strings)
                for result in self.results
            ),
            "total_string_count": sum(
                result.total_strings
                for result in self.results
            ),
            "strings_truncated": any(
                result.strings_truncated
                for result in self.results
            ),
            "results": [
                result.to_dict()
                for result in self.results
            ],
            "duration_seconds": self.duration_seconds,
            "error": self.error,
        }

@dataclass(frozen=True, slots=True)
class FlossSelection:
    """Deterministic selection of PE files for FLOSS."""

    entries: tuple[InventoryEntry, ...]
    eligible_count: int
    skipped_due_to_limit: int

_STRING_CATEGORIES = (
    ("decoded", "decoded_strings"),
    ("tight", "tight_strings"),
    ("stack", "stack_strings"),
    ("language", "language_strings"),
    (
        "language_missed",
        "language_strings_missed",
    ),
    ("static", "static_strings"),
)


def parse_floss_strings(
    output: str,
    *,
    max_strings: int = 2_000,
    max_string_chars: int = 4_096,
) -> tuple[
    tuple[FlossString, ...],
    int,
    bool,
]:
    """Parse and bound strings from FLOSS JSON output."""

    if max_strings <= 0:
        raise ValueError(
            "maximum FLOSS string count must be positive"
        )

    if max_string_chars <= 0:
        raise ValueError(
            "maximum FLOSS string length must be positive"
        )

    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"FLOSS returned invalid JSON: {exc.msg}"
        ) from exc

    if not isinstance(payload, dict):
        raise ValueError(
            "FLOSS JSON root must be an object"
        )

    raw_strings = payload.get("strings")

    if not isinstance(raw_strings, dict):
        raise ValueError(
            "FLOSS JSON is missing its strings object"
        )

    normalized: list[FlossString] = []
    total_strings = 0
    strings_truncated = False

    for kind, category_name in _STRING_CATEGORIES:
        category = raw_strings.get(
            category_name,
            [],
        )

        if not isinstance(category, list):
            raise ValueError(
                "FLOSS string category "
                f"{category_name!r} must be a list"
            )

        for index, raw_item in enumerate(category):
            if not isinstance(raw_item, dict):
                raise ValueError(
                    "FLOSS string entry "
                    f"{category_name}[{index}] "
                    "must be an object"
                )

            raw_value = raw_item.get("string")

            if not isinstance(raw_value, str):
                raise ValueError(
                    "FLOSS string entry "
                    f"{category_name}[{index}] "
                    "has an invalid string value"
                )

            raw_encoding = raw_item.get(
                "encoding"
            )

            if (
                raw_encoding is not None
                and not isinstance(
                    raw_encoding,
                    str,
                )
            ):
                raise ValueError(
                    "FLOSS string entry "
                    f"{category_name}[{index}] "
                    "has an invalid encoding"
                )

            total_strings += 1

            if len(normalized) >= max_strings:
                strings_truncated = True
                continue

            item_truncated = (
                len(raw_value) > max_string_chars
            )

            if item_truncated:
                value = (
                    raw_value[
                        : max_string_chars - 1
                    ]
                    + "…"
                )

                strings_truncated = True
            else:
                value = raw_value

            normalized.append(
                FlossString(
                    kind=kind,
                    value=value,
                    encoding=raw_encoding,
                    truncated=item_truncated,
                )
            )

    return (
        tuple(normalized),
        total_strings,
        strings_truncated,
    )


def _normalize_result(
    execution: CommandResult,
    relative_path: str,
    *,
    max_strings: int,
    max_string_chars: int,
) -> FlossResult:
    """Convert a command result into a FLOSS result."""

    issues: list[str] = []
    strings: tuple[FlossString, ...] = ()
    total_strings = 0
    strings_truncated = False

    if execution.timed_out:
        status = FlossStatus.TIMED_OUT
        issues.append(
            "FLOSS exceeded its timeout"
        )

    elif execution.return_code != 0:
        status = FlossStatus.ERROR
        issues.append(
            "FLOSS exited with unexpected code "
            f"{execution.return_code}"
        )

    elif execution.output_truncated:
        status = FlossStatus.ERROR
        issues.append(
            "FLOSS output exceeded its byte limit"
        )

    else:
        try:
            (
                strings,
                total_strings,
                strings_truncated,
            ) = parse_floss_strings(
                execution.stdout,
                max_strings=max_strings,
                max_string_chars=max_string_chars,
            )
        except ValueError as exc:
            status = FlossStatus.ERROR
            issues.append(str(exc))
        else:
            status = FlossStatus.COMPLETED

    complete = (
        status == FlossStatus.COMPLETED
        and not execution.timed_out
        and not execution.output_truncated
    )

    return FlossResult(
        status=status,
        complete=complete,
        relative_path=relative_path,
        return_code=execution.return_code,
        strings=strings,
        total_strings=total_strings,
        strings_truncated=strings_truncated,
        timed_out=execution.timed_out,
        output_truncated=(
            execution.output_truncated
        ),
        duration_seconds=(
            execution.duration_seconds
        ),
        stdout=execution.stdout,
        stderr=execution.stderr,
        error="; ".join(issues) or None,
    )


def run_floss(
    target: Path,
    scan_root: Path,
    *,
    executable: str = "floss",
    timeout_seconds: float = 600.0,
    max_output_bytes: int = 16_000_000,
    max_strings: int = 2_000,
    max_string_chars: int = 4_096,
) -> FlossResult:
    """Extract non-static strings from one PE binary."""

    if not target.is_absolute():
        raise ValueError(
            "FLOSS target must be absolute"
        )

    if not scan_root.is_absolute():
        raise ValueError(
            "FLOSS scan root must be absolute"
        )

    try:
        relative = target.relative_to(
            scan_root
        )
    except ValueError as exc:
        raise ValueError(
            "FLOSS target must be beneath "
            "the scan root"
        ) from exc

    if ".." in relative.parts:
        raise ValueError(
            "FLOSS target must be beneath "
            "the scan root"
        )

    if target.is_symlink():
        raise ValueError(
            "FLOSS target cannot be a symlink"
        )

    if not target.is_file():
        raise ValueError(
            "FLOSS target must be a regular file"
        )

    command = [
        executable,
        "-j",
        "--no",
        "static",
        "--",
        str(target),
    ]

    execution = run_command(
        command,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        env={
            "PATH": (
                "/opt/floss-venv/bin:"
                "/usr/local/bin:/usr/bin:/bin"
            ),
            "LC_ALL": "C",
            "LANG": "C",
            "HOME": "/tmp/floss-home",
            "XDG_CACHE_HOME": "/tmp/floss-cache",
            "XDG_CONFIG_HOME": "/tmp/floss-config",
            "USER": "static-triage",
            "LOGNAME": "static-triage",
        },
    )

    return _normalize_result(
        execution,
        relative.as_posix(),
        max_strings=max_strings,
        max_string_chars=max_string_chars,
    )

_FLOSS_ROUTING_CLASSES = frozenset(
    {
        RoutingClass.PE_EXECUTABLE,
        RoutingClass.PE_DLL,
    }
)


def select_floss_entries(
    entries: list[InventoryEntry],
    *,
    max_files: int,
) -> FlossSelection:
    """Select inventory-approved PE files for FLOSS."""

    if max_files <= 0:
        raise ValueError(
            "maximum FLOSS file count must be positive"
        )

    eligible = [
        entry
        for entry in entries
        if (
            entry.kind == EntryKind.REGULAR_FILE
            and entry.state == EntryState.INVENTORIED
            and entry.routing_class
            in _FLOSS_ROUTING_CLASSES
        )
    ]

    eligible.sort(
        key=lambda entry: os.fsencode(
            entry.relative_path
        )
    )

    selected = eligible[:max_files]

    return FlossSelection(
        entries=tuple(selected),
        eligible_count=len(eligible),
        skipped_due_to_limit=(
            len(eligible) - len(selected)
        ),
    )

def run_floss_batch(
    entries: list[InventoryEntry],
    scan_root: Path,
    *,
    executable: str = "floss",
    max_files: int = 50,
    file_timeout_seconds: float = 600.0,
    total_timeout_seconds: float = 3600.0,
    max_output_bytes: int = 16_000_000,
    max_strings: int = 2_000,
    max_string_chars: int = 4_096,
) -> FlossBatchResult:
    """Run FLOSS over a bounded set of eligible PE files."""

    if file_timeout_seconds <= 0:
        raise ValueError(
            "FLOSS file timeout must be positive"
        )

    if total_timeout_seconds <= 0:
        raise ValueError(
            "FLOSS total timeout must be positive"
        )

    if max_output_bytes <= 0:
        raise ValueError(
            "FLOSS output limit must be positive"
        )

    if max_strings <= 0:
        raise ValueError(
            "maximum FLOSS string count must be positive"
        )

    if max_string_chars <= 0:
        raise ValueError(
            "maximum FLOSS string length must be positive"
        )

    selection = select_floss_entries(
        entries,
        max_files=max_files,
    )

    started = time.monotonic()
    results: list[FlossResult] = []

    for entry in selection.entries:
        elapsed = time.monotonic() - started
        remaining = total_timeout_seconds - elapsed

        if remaining <= 0:
            break

        effective_timeout = min(
            file_timeout_seconds,
            remaining,
        )

        file_target = (
            scan_root
            / Path(entry.relative_path)
        )

        try:
            result = run_floss(
                file_target,
                scan_root,
                executable=executable,
                timeout_seconds=effective_timeout,
                max_output_bytes=max_output_bytes,
                max_strings=max_strings,
                max_string_chars=max_string_chars,
            )
        except (OSError, ValueError) as exc:
            result = FlossResult(
                status=FlossStatus.ERROR,
                complete=False,
                relative_path=entry.relative_path,
                return_code=-1,
                strings=(),
                total_strings=0,
                strings_truncated=False,
                timed_out=False,
                output_truncated=False,
                duration_seconds=0.0,
                stdout="",
                stderr="",
                error=(
                    "FLOSS analysis could not start: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

        results.append(result)

    skipped_due_to_timeout = (
        len(selection.entries) - len(results)
    )

    issues: list[str] = []

    if selection.skipped_due_to_limit:
        issues.append(
            f"{selection.skipped_due_to_limit} eligible "
            "files exceeded the FLOSS file-count limit"
        )

    if skipped_due_to_timeout:
        issues.append(
            f"{skipped_due_to_timeout} selected files "
            "were not analyzed before the FLOSS "
            "total-time limit"
        )

    failed_files = sum(
        not result.complete
        for result in results
    )

    if failed_files:
        issues.append(
            f"{failed_files} FLOSS analyses were incomplete"
        )

    complete = (
        selection.skipped_due_to_limit == 0
        and skipped_due_to_timeout == 0
        and failed_files == 0
    )

    return FlossBatchResult(
        status=(
            FlossBatchStatus.COMPLETED
            if complete
            else FlossBatchStatus.PARTIAL
        ),
        complete=complete,
        eligible_files=selection.eligible_count,
        attempted_files=len(results),
        skipped_due_to_limit=(
            selection.skipped_due_to_limit
        ),
        skipped_due_to_timeout=(
            skipped_due_to_timeout
        ),
        results=tuple(results),
        duration_seconds=(
            time.monotonic() - started
        ),
        error="; ".join(issues) or None,
    )