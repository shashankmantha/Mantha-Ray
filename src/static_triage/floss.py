from __future__ import annotations

import json
import time

from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any

from .file_progress import FileProgress
from . import plain_strings
from .memory_budget import estimate_mib, memory_policy
from .parallel import (
    looks_memory_killed,
    run_groups,
    scaled_timeout,
    timeout_policy,
)
from .scheduling import (
    SCHEDULING_POLICY,
    in_path_order,
    prioritize_groups,
)
from .deduplication import (
    AnalysisGroup,
    group_entries_by_sha256,
)
from .models import (
    EntryKind,
    EntryState,
    InventoryEntry,
    RoutingClass,
)
from .runner import CommandResult, run_command


# FLOSS refuses to deobfuscate strings from files larger than this
# (floss.const.MAX_FILE_SIZE in FLOSS 3.x). Such files are reported as
# not applicable for FLOSS instead of failing after launch.
FLOSS_MAX_FILE_BYTES = 16 * 1024 * 1024

_FLOSS_SIZE_REFUSAL = "cannot deobfuscate strings from files larger than"

# FLOSS's emulation (stack, tight and decoded strings) is only run on
# files up to this size. Measured on Door Kickers 2 (2026-10-21, alone,
# 6 GiB): 2 MB libraries took 9-12 min, but 6.8-8.1 MB game executables
# failed after 47 min or ran past 60 min. Bigger files, including those
# over FLOSS's own 16 MiB limit, get a fast plain-strings pass instead.
FLOSS_EMULATION_MAX_BYTES = 4 * 1024 * 1024

# Budget and memory the plain-strings pass plans with; it takes seconds.
PLAIN_TIMEOUT_SECONDS = 300.0
PLAIN_MEMORY_MIB = 512

EMULATION = "emulation"
PLAIN = "plain"


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
    # Why a plain string was kept, e.g. "url" or "miner pool".
    category: str | None = None

    def to_dict(self) -> dict[str, Any]:
        record = {
            "kind": self.kind,
            "value": self.value,
            "encoding": self.encoding,
            "truncated": self.truncated,
        }
        if self.category is not None:
            record["category"] = self.category
        return record


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
    reused_for: tuple[str, ...] = ()
    # 1-based position in which this file was analyzed.
    analysis_position: int | None = None
    # The time limit this file was given, after size scaling and budget.
    timeout_seconds: float | None = None
    # Timed out only because the stage's time budget ran out.
    stopped_at_budget_end: bool = False
    # Killed for memory while sharing the container, then run alone.
    retried_alone: bool = False
    first_attempt: dict[str, Any] | None = None
    # Highest resident memory measured for the analysis process.
    peak_memory_mib: float | None = None
    # Memory reserved for it when scheduling, if a budget was set.
    memory_estimate_mib: int | None = None
    # Ran out of memory with nothing else running: the profile is too small.
    needs_more_memory: bool = False
    # "emulation" (FLOSS proper) or "plain" (fast pass for big files).
    mode: str = EMULATION
    # For plain mode: whether the whole file was read.
    fully_scanned: bool | None = None

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
            "reused_for": list(self.reused_for),
            "analysis_position": self.analysis_position,
            "timeout_seconds": self.timeout_seconds,
            "stopped_at_budget_end": self.stopped_at_budget_end,
            "retried_alone": self.retried_alone,
            "first_attempt": self.first_attempt,
            "peak_memory_mib": self.peak_memory_mib,
            "memory_estimate_mib": self.memory_estimate_mib,
            "needs_more_memory": self.needs_more_memory,
            "mode": self.mode,
            "fully_scanned": self.fully_scanned,
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
    unique_eligible_files: int | None = None
    duplicate_analyses_avoided: int = 0
    scheduling_policy: str = SCHEDULING_POLICY
    workers: int = 1
    file_timeout_policy: dict[str, float] | None = None
    memory_policy: dict[str, Any] | None = None
    skipped_size_paths: tuple[str, ...] = ()

    @property
    def skipped_due_to_size(self) -> int:
        return len(self.skipped_size_paths)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "scheduling_policy": self.scheduling_policy,
            "workers": self.workers,
            "file_timeout_policy": self.file_timeout_policy,
            "memory_policy": self.memory_policy,
            "size_limit_bytes": FLOSS_MAX_FILE_BYTES,
            "emulation_max_bytes": FLOSS_EMULATION_MAX_BYTES,
            "plain_strings_files": sum(
                result.mode == PLAIN for result in self.results
            ),
            "skipped_due_to_size": self.skipped_due_to_size,
            "skipped_size_paths": list(self.skipped_size_paths),
            "complete": self.complete,
            "eligible_files": self.eligible_files,
            "unique_eligible_files": (
                self.unique_eligible_files
                if self.unique_eligible_files is not None
                else self.eligible_files
            ),
            "attempted_files": self.attempted_files,
            "duplicate_analyses_avoided": (
                self.duplicate_analyses_avoided
            ),
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
    groups: tuple[AnalysisGroup, ...] = ()
    unique_eligible_count: int = 0
    oversized_paths: tuple[str, ...] = ()


def wants_plain_strings(entry: InventoryEntry) -> bool:
    size = entry.size_bytes
    return (
        isinstance(size, int)
        and not isinstance(size, bool)
        and size > FLOSS_EMULATION_MAX_BYTES
    )


def _exceeds_floss_limit(entry: InventoryEntry) -> bool:
    size = entry.size_bytes
    return (
        isinstance(size, int)
        and not isinstance(size, bool)
        and size > FLOSS_MAX_FILE_BYTES
    )


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
                    + "\u2026"
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

    elif (
        execution.return_code != 0
        and _FLOSS_SIZE_REFUSAL in execution.stderr
    ):
        status = FlossStatus.ERROR
        issues.append(
            "FLOSS refused the file because it exceeds "
            "its 16 MiB deobfuscation limit"
        )

    elif looks_memory_killed(
        execution.return_code,
        execution.timed_out,
    ):
        status = FlossStatus.ERROR
        issues.append(
            "FLOSS was killed (exit code "
            f"{execution.return_code}), most likely because the "
            "container ran out of memory"
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
        peak_memory_mib=execution.peak_memory_mib,
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

    groups = prioritize_groups(group_entries_by_sha256(eligible))
    # Big files get the fast plain-strings pass, first, so they are always
    # covered; they don't count against the file cap.
    plain_groups = [
        group for group in groups
        if wants_plain_strings(group.representative)
    ]
    emulation_groups = [
        group for group in groups
        if not wants_plain_strings(group.representative)
    ]
    selected_groups = (
        tuple(plain_groups) + tuple(emulation_groups[:max_files])
    )

    return FlossSelection(
        entries=tuple(group.representative for group in selected_groups),
        eligible_count=len(eligible),
        skipped_due_to_limit=sum(
            len(group.entries) for group in emulation_groups[max_files:]
        ),
        groups=selected_groups,
        unique_eligible_count=len(groups),
    )


def run_plain_strings(
    target: Path,
    scan_root: Path,
) -> FlossResult:
    relative = target.relative_to(scan_root)
    if ".." in relative.parts or target.is_symlink() or not target.is_file():
        raise ValueError("plain-strings target must be a regular file beneath the scan root")
    started = time.monotonic()
    found = plain_strings.extract(target)
    duration = time.monotonic() - started
    issues = []
    if not found.fully_scanned:
        issues.append(
            "plain strings: only the first "
            f"{found.scanned_bytes // (1024 * 1024)} MiB were read"
        )
    return FlossResult(
        status=FlossStatus.COMPLETED,
        complete=found.fully_scanned,
        relative_path=relative.as_posix(),
        return_code=0,
        strings=tuple(
            FlossString(
                kind="static",
                value=match.value,
                encoding=match.encoding,
                truncated=match.truncated,
                category=match.category,
            )
            for match in found.matches
        ),
        total_strings=found.total_strings,
        strings_truncated=found.matches_truncated,
        timed_out=False,
        output_truncated=False,
        duration_seconds=duration,
        stdout="",
        stderr="",
        error="; ".join(issues) or None,
        mode=PLAIN,
        fully_scanned=found.fully_scanned,
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
    on_file: FileProgress | None = None,
    workers: int = 1,
    file_timeout_max_seconds: float | None = None,
    memory_budget_mib: int | None = None,
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

    if workers < 1:
        raise ValueError(
            "FLOSS needs at least one worker"
        )

    selection = select_floss_entries(
        entries,
        max_files=max_files,
    )

    started = time.monotonic()
    max_timeout = (
        file_timeout_seconds
        if file_timeout_max_seconds is None
        else max(file_timeout_seconds, file_timeout_max_seconds)
    )

    def analyze(group: AnalysisGroup, timeout: float) -> FlossResult:
        entry = group.representative
        if wants_plain_strings(entry):
            try:
                return run_plain_strings(
                    scan_root / Path(entry.relative_path),
                    scan_root,
                )
            except (OSError, ValueError) as exc:
                return FlossResult(
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
                        "plain-strings pass failed: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                    mode=PLAIN,
                )
        try:
            return run_floss(
                scan_root / Path(entry.relative_path),
                scan_root,
                executable=executable,
                timeout_seconds=timeout,
                max_output_bytes=max_output_bytes,
                max_strings=max_strings,
                max_string_chars=max_string_chars,
            )
        except (OSError, ValueError) as exc:
            return FlossResult(
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

    run = run_groups(
        selection.groups,
        analyze,
        label="FLOSS",
        workers=workers,
        total_timeout_seconds=total_timeout_seconds,
        timeout_for=lambda group: (
            PLAIN_TIMEOUT_SECONDS
            if wants_plain_strings(group.representative)
            else scaled_timeout(
                group.representative.size_bytes,
                base_seconds=file_timeout_seconds,
                max_seconds=max_timeout,
            )
        ),
        outcome=lambda result: (
            result.complete,
            result.timed_out,
            result.duration_seconds,
        ),
        # Looked up at call time so tests can substitute the clock.
        clock=lambda: time.monotonic(),
        started_at=started,
        on_file=on_file,
        detail_for=lambda group: (
            "plain strings" if wants_plain_strings(group.representative) else None
        ),
        retry_alone_if=lambda result: looks_memory_killed(
            result.return_code,
            result.timed_out,
        ),
        memory_budget_mib=memory_budget_mib,
        memory_for=lambda group: (
            PLAIN_MEMORY_MIB
            if wants_plain_strings(group.representative)
            else estimate_mib("floss", group.representative.size_bytes)
        ),
    )

    results = [
        replace(
            item.result,
            reused_for=item.group.reused_paths,
            analysis_position=item.position,
            timeout_seconds=item.timeout_seconds,
            stopped_at_budget_end=(
                item.result.timed_out and item.capped_by_budget
            ),
            retried_alone=item.first_attempt is not None,
            first_attempt=(
                None
                if item.first_attempt is None
                else {
                    "return_code": item.first_attempt.return_code,
                    "duration_seconds": item.first_attempt.duration_seconds,
                    "error": item.first_attempt.error,
                }
            ),
            peak_memory_mib=item.result.peak_memory_mib,
            memory_estimate_mib=item.memory_estimate_mib,
            needs_more_memory=(
                not item.shared
                and looks_memory_killed(
                    item.result.return_code,
                    item.result.timed_out,
                )
            ),
        )
        for item in run.finished
    ]
    analyzed_groups = [item.group for item in run.finished]

    skipped_due_to_timeout = sum(
        len(group.entries) for group in run.not_started
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

    too_big = sum(result.needs_more_memory for result in results)
    if too_big:
        issues.append(
            f"{too_big} FLOSS analyses ran out of memory even when "
            "run alone; this profile needs more memory for them"
        )

    budget_stopped = sum(
        result.stopped_at_budget_end for result in results
    )
    if budget_stopped:
        issues.append(
            f"{budget_stopped} of them stopped at the end of the "
            "time budget"
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
        results=in_path_order(results),
        duration_seconds=(
            time.monotonic() - started
        ),
        error="; ".join(issues) or None,
        unique_eligible_files=(
            selection.unique_eligible_count
        ),
        duplicate_analyses_avoided=sum(
            group.duplicate_count
            for group in analyzed_groups
        ),
        skipped_size_paths=(),
        workers=workers,
        file_timeout_policy=timeout_policy(
            file_timeout_seconds,
            max_timeout,
        ),
        memory_policy=(
            memory_policy("floss", memory_budget_mib)
            if memory_budget_mib is not None
            else None
        ),
    )