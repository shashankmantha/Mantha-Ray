from __future__ import annotations

from collections.abc import Callable

from .deduplication import AnalysisGroup

# Receives one human-readable line per analyzer file event.
FileProgress = Callable[[str], None]

# File names come from the sample, so they are untrusted. Keep messages
# short and single-line; the UI also replaces control characters.
MAX_PATH_CHARS = 100

_CONTROL = {code: "?" for code in (*range(0x20), *range(0x7F, 0xA0))}


def short_path(path: str) -> str:
    clean = path.translate(_CONTROL)
    if len(clean) <= MAX_PATH_CHARS:
        return clean
    return "…" + clean[-(MAX_PATH_CHARS - 1):]


def format_size(size: int | None) -> str:
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        return "size unknown"
    if size < 1024:
        return f"{size} B"
    if size < 1024**2:
        return f"{size / 1024:.0f} KB"
    if size < 1024**3:
        return f"{size / 1024**2:.1f} MB"
    return f"{size / 1024**3:.1f} GB"


def format_duration(seconds: float) -> str:
    total = max(0, int(round(seconds)))
    minutes, secs = divmod(total, 60)
    if minutes and secs:
        return f"{minutes} min {secs} s"
    if minutes:
        return f"{minutes} min"
    return f"{secs} s"


def _subject(group: AnalysisGroup) -> str:
    subject = short_path(group.representative.relative_path)
    copies = group.duplicate_count
    if copies:
        plural = "copy" if copies == 1 else "copies"
        subject += f" (+{copies} identical {plural})"
    return subject


def started_message(
    analyzer: str,
    position: int,
    total: int,
    group: AnalysisGroup,
    *,
    alone: bool = False,
) -> str:
    size = format_size(group.representative.size_bytes)
    verb = "started alone" if alone else "started"
    return f"{analyzer} {position}/{total} {verb}: {_subject(group)} ({size})"


def finished_message(
    analyzer: str,
    position: int,
    total: int,
    group: AnalysisGroup,
    *,
    complete: bool,
    timed_out: bool,
    duration_seconds: float,
    stopped_at_budget_end: bool = False,
) -> str:
    took = format_duration(duration_seconds)
    if stopped_at_budget_end:
        outcome = f"stopped at the end of the time budget after {took}"
    elif timed_out:
        outcome = f"timed out after {took}"
    elif complete:
        outcome = f"completed in {took}"
    else:
        outcome = f"failed after {took}"
    return f"{analyzer} {position}/{total} {outcome}: {_subject(group)}"

def memory_retry_message(
    analyzer: str,
    position: int,
    total: int,
    group: AnalysisGroup,
    duration_seconds: float,
) -> str:
    took = format_duration(duration_seconds)
    return (
        f"{analyzer} {position}/{total} ran out of memory after {took}; "
        f"will retry alone when the other analyses finish: {_subject(group)}"
    )