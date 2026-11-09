from __future__ import annotations

from typing import Any, Iterable

from .capa import _CAPA_ROUTING_CLASSES, CapaBatchResult
from .clamav import ClamAVResult, ClamAVStatus
from .floss import _FLOSS_ROUTING_CLASSES, PLAIN, FlossBatchResult
from .models import EntryKind, EntryState, InventoryEntry, ToolInfo
from .yara_scan import YARA_MAX_FILE_BYTES, YaraBatchResult

COVERAGE_VERSION = 1
MAX_REPORTED_GAPS = 5000

DONE = "done"
FINDING = "finding"
PARTIAL = "partial"
NOT_REACHED = "not_reached"
TIMED_OUT = "timed_out"
TOO_LARGE = "too_large"
FAILED = "failed"
STOPPED = "stopped"
NOT_RUN = "not_run"

CHECKED = frozenset({DONE, FINDING})
STATUSES = (DONE, FINDING, PARTIAL, NOT_REACHED, TIMED_OUT, TOO_LARGE, FAILED, STOPPED, NOT_RUN)
ANALYZERS = ("inventory", "clamav", "yara", "capa", "floss")
TOOL_NAMES = {"clamav": "clamscan", "yara": "yr", "capa": "capa", "floss": "floss"}
LABELS = {"clamav": "ClamAV", "yara": "YARA-X", "capa": "capa", "floss": "FLOSS"}

Outcome = tuple[str, str | None]


def _paths(result: Any) -> Iterable[str]:
    yield result.relative_path
    yield from result.reused_for


def _not_run(analyzer: str, tools: list[ToolInfo], stopped: bool) -> Outcome:
    label = LABELS[analyzer]
    tool = next((t for t in tools if t.name == TOOL_NAMES[analyzer]), None)
    if tool is not None and not tool.available:
        return NOT_RUN, f"{label} was unavailable"
    if stopped:
        return STOPPED, "the scan was stopped before this stage"
    return NOT_RUN, f"{label} did not run"


def _clamav(
    files: list[InventoryEntry], result: ClamAVResult | None, tools: list[ToolInfo], stopped: bool,
) -> dict[str, Outcome]:
    if result is None:
        outcome = _not_run("clamav", tools, stopped)
        return {entry.relative_path: outcome for entry in files}
    findings = {finding.relative_path for finding in result.findings}
    limits = {hit.relative_path: hit for hit in result.limits_exceeded}
    if result.whole_run_complete:
        default: Outcome = (DONE, None)
    elif result.stopped_by_user:
        default = (STOPPED, "the scan was stopped before ClamAV finished")
    elif result.status is ClamAVStatus.TIMED_OUT:
        default = (TIMED_OUT, "ClamAV ran out of time before finishing")
    else:
        default = (FAILED, result.error or "ClamAV did not finish")
    outcomes: dict[str, Outcome] = {}
    for entry in files:
        path = entry.relative_path
        if path in findings:
            outcomes[path] = (FINDING, None)
        elif path in limits:
            hit = limits[path]
            status = {"MaxFileSize": TOO_LARGE, "MaxScanTime": TIMED_OUT}.get(hit.limit, PARTIAL)
            outcomes[path] = (status, hit.reason)
        else:
            outcomes[path] = default
    return outcomes


def _yara(
    files: list[InventoryEntry], result: YaraBatchResult | None, tools: list[ToolInfo], stopped: bool,
) -> dict[str, Outcome]:
    if result is None:
        outcome = _not_run("yara", tools, stopped)
        return {entry.relative_path: outcome for entry in files}
    if result.status == "unavailable":
        # No rule packs are installed. Like the verdict, coverage treats
        # YARA-X as optional then, and says so in a note.
        return {}
    if result.status == "error":
        return {entry.relative_path: (FAILED, result.error) for entry in files}
    seen: dict[str, Outcome] = {}
    for file_result in result.results:
        if file_result.matches:
            outcome: Outcome = (FINDING, None)
        elif file_result.complete:
            outcome = (DONE, None)
        elif file_result.stopped_by_user:
            outcome = (STOPPED, "the scan was stopped while YARA-X was scanning it")
        elif file_result.timed_out:
            outcome = (TIMED_OUT, "YARA-X timed out on it")
        else:
            outcome = (FAILED, file_result.error or "YARA-X failed on it")
        for path in _paths(file_result):
            seen[path] = outcome
    never = (
        (STOPPED, "the scan was stopped before YARA-X reached it")
        if stopped
        else (NOT_REACHED, "YARA-X's total time limit ran out before it")
    )
    outcomes: dict[str, Outcome] = {}
    for entry in files:
        size = entry.size_bytes
        if not isinstance(size, int) or size > YARA_MAX_FILE_BYTES:
            outcomes[entry.relative_path] = (
                TOO_LARGE, f"larger than YARA-X's {YARA_MAX_FILE_BYTES // 1024**3} GiB limit",
            )
        else:
            outcomes[entry.relative_path] = seen.get(entry.relative_path, never)
    return outcomes


def _analysis_outcome(result: Any, label: str) -> Outcome:
    if getattr(result, "stopped_by_user", False):
        return STOPPED, f"the scan was stopped while {label} was analyzing it"
    if getattr(result, "needs_more_memory", False):
        return FAILED, f"{label} ran out of memory; a bigger resource profile may finish it"
    if getattr(result, "stopped_at_budget_end", False):
        return TIMED_OUT, f"{label}'s time budget ran out while analyzing it"
    if result.timed_out:
        return TIMED_OUT, f"{label} timed out on it"
    return FAILED, result.error or f"{label} failed on it"


def _never_reached(label: str, result: Any, stopped: bool) -> Outcome:
    if stopped:
        return STOPPED, f"the scan was stopped before {label} reached it"
    by_limit = result.skipped_due_to_limit > 0
    by_time = result.skipped_due_to_timeout > 0
    if by_limit and not by_time:
        return NOT_REACHED, f"over {label}'s file limit for one scan"
    if by_time and not by_limit:
        return NOT_REACHED, f"{label}'s time budget ran out before it"
    return NOT_REACHED, f"{label}'s file limit or time budget was reached first"


def _capa(
    files: list[InventoryEntry], result: CapaBatchResult | None, tools: list[ToolInfo], stopped: bool,
) -> dict[str, Outcome]:
    if result is None:
        outcome = _not_run("capa", tools, stopped)
        return {entry.relative_path: outcome for entry in files}
    seen: dict[str, Outcome] = {}
    for file_result in result.results:
        outcome = (DONE, None) if file_result.complete else _analysis_outcome(file_result, "capa")
        for path in _paths(file_result):
            seen[path] = outcome
    never = _never_reached("capa", result, stopped)
    return {entry.relative_path: seen.get(entry.relative_path, never) for entry in files}


def _floss(
    files: list[InventoryEntry], result: FlossBatchResult | None, tools: list[ToolInfo], stopped: bool,
) -> dict[str, Outcome]:
    if result is None:
        outcome = _not_run("floss", tools, stopped)
        return {entry.relative_path: outcome for entry in files}
    seen: dict[str, Outcome] = {}
    for file_result in result.results:
        if not file_result.complete:
            outcome = _analysis_outcome(file_result, "FLOSS")
        elif file_result.mode == PLAIN and file_result.fully_scanned is False:
            outcome = (PARTIAL, "only part of the file was read for plain strings")
        elif file_result.mode == PLAIN:
            outcome = (PARTIAL, "plain strings only; too large for FLOSS's decoding")
        else:
            outcome = (DONE, None)
        for path in _paths(file_result):
            seen[path] = outcome
    for path in result.skipped_size_paths:
        seen.setdefault(path, (TOO_LARGE, "larger than FLOSS can analyze"))
    never = _never_reached("FLOSS", result, stopped)
    return {entry.relative_path: seen.get(entry.relative_path, never) for entry in files}


def _inventory_gap(entry: InventoryEntry) -> Outcome:
    if entry.state == EntryState.LIMIT_EXCEEDED:
        return TOO_LARGE, entry.error or "over an inventory limit"
    if entry.state == EntryState.SKIPPED:
        return NOT_RUN, entry.error or "skipped during inventory"
    return FAILED, entry.error or "could not be read"


def build_coverage(
    entries: list[InventoryEntry],
    *,
    tools: list[ToolInfo],
    clamav_result: ClamAVResult | None,
    yara_result: YaraBatchResult | None,
    capa_result: CapaBatchResult | None,
    floss_result: FlossBatchResult | None,
    stopped: bool = False,
    changed_paths: Iterable[str] = (),
) -> dict[str, Any]:
    """Says, for every regular file, which analyzers fully checked it."""

    regular = [entry for entry in entries if entry.kind == EntryKind.REGULAR_FILE]
    readable = [entry for entry in regular if entry.state == EntryState.INVENTORIED]
    changed = set(changed_paths)
    inventory_gaps = {
        entry.relative_path: _inventory_gap(entry)
        for entry in regular
        if entry.state != EntryState.INVENTORIED
    }
    for path in changed:
        # Its results describe the file as it was when first read.
        inventory_gaps[path] = (FAILED, "changed while the scan was running")
    by_analyzer: dict[str, dict[str, Outcome]] = {
        "inventory": inventory_gaps,
        "clamav": _clamav(readable, clamav_result, tools, stopped),
        "yara": _yara(readable, yara_result, tools, stopped),
        "capa": _capa(
            [e for e in readable if e.routing_class in _CAPA_ROUTING_CLASSES],
            capa_result, tools, stopped,
        ),
        "floss": _floss(
            [e for e in readable if e.routing_class in _FLOSS_ROUTING_CLASSES],
            floss_result, tools, stopped,
        ),
    }

    gaps: list[dict[str, Any]] = []
    worst: dict[str, str] = {}  # path -> "partial" or "gap"
    analyzers: dict[str, dict[str, int]] = {}
    for analyzer in ANALYZERS:
        outcomes = by_analyzer[analyzer]
        counts = {"applicable": len(outcomes)}
        for status in STATUSES:
            counts[status] = 0
        for path, (status, reason) in outcomes.items():
            counts[status] += 1
            if status in CHECKED:
                continue
            gaps.append({
                "relative_path": path, "analyzer": analyzer, "status": status, "reason": reason,
            })
            if status == PARTIAL:
                worst.setdefault(path, PARTIAL)
            else:
                worst[path] = "gap"
        analyzers[analyzer] = {key: value for key, value in counts.items() if value or key == "applicable"}

    with_gaps = sum(1 for value in worst.values() if value == "gap")
    partially = sum(1 for value in worst.values() if value == PARTIAL)
    gaps.sort(key=lambda gap: (gap["status"] == PARTIAL, gap["relative_path"], ANALYZERS.index(gap["analyzer"])))

    notes: list[str] = []
    other = len(entries) - len(regular) - sum(e.kind == EntryKind.DIRECTORY for e in entries)
    if other:
        notes.append(
            f"{other} symlink{'s' if other != 1 else ''} or special "
            f"{'files were' if other != 1 else 'file was'} listed but not followed or scanned."
        )
    if yara_result is not None and yara_result.status == "unavailable":
        notes.append(
            "YARA-X had no rule packs, so it isn't counted: "
            + (yara_result.error or "no rule packs are installed").rstrip(".")
            + ". Install them with \"mantha-ray packs update\"."
        )
    reused = [
        (label, sum(1 for r in batch.results if r.cached_from))
        for label, batch in (("capa", capa_result), ("FLOSS", floss_result))
        if batch is not None
    ]
    reused = [(label, count) for label, count in reused if count]
    if reused:
        notes.append(
            "Reused from earlier scans of identical files (same SHA-256): "
            + ", ".join(f"{count} {label} {'result' if count == 1 else 'results'}" for label, count in reused)
            + ". They count as checked; report.json says which case each came from."
        )
    if partially:
        notes.append(
            "Partly checked files had every analyzer run, but at least one could only do a "
            "reduced pass (for example plain strings instead of FLOSS's decoding)."
        )

    return {
        "version": COVERAGE_VERSION,
        "files": len(regular),
        "fully_checked": len(regular) - with_gaps - partially,
        "partially_checked": partially,
        "with_gaps": with_gaps,
        "analyzers": analyzers,
        "notes": notes,
        "gap_count": len(gaps),
        "gaps": gaps[:MAX_REPORTED_GAPS],
        "gaps_truncated": len(gaps) > MAX_REPORTED_GAPS,
    }


def headline(coverage: dict[str, Any]) -> str:
    files = coverage.get("files", 0)
    full = coverage.get("fully_checked", 0)
    parts = []
    if coverage.get("partially_checked"):
        parts.append(f"{coverage['partially_checked']:,} partly checked")
    if coverage.get("with_gaps"):
        parts.append(f"{coverage['with_gaps']:,} with gaps")
    tail = f" ({', '.join(parts)})" if parts else ""
    return f"Fully checked: {full:,} of {files:,} file{'s' if files != 1 else ''}{tail}"
