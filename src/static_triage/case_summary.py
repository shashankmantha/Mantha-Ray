from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from .capa_risk import RISK_POLICY_VERSION, find_combinations
from .coverage import headline
from .file_progress import format_duration, format_size

DEFAULT_RESULTS = Path.home() / "mantha-ray-results"
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_ORDER_LINES = 40
MAX_GAP_LINES = 20

_CASE_NAME = re.compile(r"^case-\d{8}T\d{6}Z-[0-9a-f]{8}$")
_CONTROL = {code: "?" for code in (*range(0x20), *range(0x7F, 0xA0))}


def clean(value: object, limit: int = 160) -> str:
    # Report text can come from the sample. Strip control characters so
    # it cannot inject terminal escape sequences.
    text = str(value).translate(_CONTROL)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def find_case(target: Path) -> Path:
    target = target.expanduser()
    if (target / "report.json").is_file():
        return target
    if not target.is_dir():
        raise SystemExit(f"No case or results folder at {clean(target)}")
    cases = sorted(
        (
            entry
            for entry in target.iterdir()
            if _CASE_NAME.fullmatch(entry.name)
            and not entry.is_symlink()
            and (entry / "report.json").is_file()
        ),
        key=lambda entry: entry.name,
    )
    if not cases:
        raise SystemExit(f"No saved cases in {clean(target)}")
    return cases[-1]


def load_report(case: Path) -> dict[str, Any]:
    path = case / "report.json"
    if path.is_symlink() or path.stat().st_size > MAX_REPORT_BYTES:
        raise SystemExit("report.json is missing or too large")
    report = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(report, dict):
        raise SystemExit("report.json is not a JSON object")
    return report


def _number(value: object) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def profile_line(report: dict[str, Any]) -> str:
    resources = report.get("resources")
    if not isinstance(resources, dict):
        return "not recorded (older case)"
    name = clean(resources.get("profile", "unknown"), 32)
    base = clean(resources.get("base", ""), 32)
    title = f"Custom (based on {base.title()})" if name == "custom" else name.title()
    values = resources.get("values") or {}
    parts = [title]
    cpus = _number(values.get("cpus"))
    memory = _number(values.get("memory_mib"))
    if cpus is not None:
        parts.append(f"{cpus:g} CPUs")
    if memory is not None:
        parts.append(f"{memory / 1024:g} GiB")
    workers = _number(resources.get("workers"))
    if workers is not None:
        parts.append(f"{workers:g} parallel")
    enforced = resources.get("enforced")
    if enforced is True:
        parts.append("limits confirmed")
    elif enforced is False:
        missing = resources.get("not_enforced") or []
        parts.append(
            "NOT confirmed: " + ", ".join(clean(item, 24) for item in missing)
        )
    return " · ".join(parts)


def timings_line(report: dict[str, Any]) -> str:
    timings = report.get("stage_timings")
    if not isinstance(timings, dict) or not timings:
        return "not recorded (older case)"
    parts = []
    for stage in ("inventory", "clamav", "yara", "capa", "floss"):
        record = timings.get(stage)
        if not isinstance(record, dict):
            continue
        seconds = _number(record.get("duration_seconds"))
        shown = format_duration(seconds) if seconds is not None else "—"
        parts.append(f"{stage} {shown}")
    return " · ".join(parts)


def yara_line(data: object) -> str:
    if not isinstance(data, dict):
        return "not part of this scan (older case)"
    status = data.get("status")
    if status == "unavailable":
        return "no rule packs installed"
    if status in ("not_run", "error"):
        return clean(f"{status}: {data.get('error') or ''}", 160)
    bundle = data.get("bundle") if isinstance(data.get("bundle"), dict) else {}
    counts = data.get("severity_counts") if isinstance(data.get("severity_counts"), dict) else {}
    found = ", ".join(
        f"{_number(counts.get(s)) or 0:g} {s}" for s in ("threat", "suspicious", "info")
        if _number(counts.get(s))
    ) or "no matches"
    signed = "" if bundle.get("verified") else ", unsigned"
    return clean(
        f"{status} · {data.get('scanned_files', 0)} files · {found}"
        f" · bundle {bundle.get('version', '?')}{signed}",
        200,
    )


def analyzer_lines(name: str, data: object) -> list[str]:
    if not isinstance(data, dict):
        return [f"{name}: not recorded"]
    if data.get("status") == "not_run":
        return [f"{name}: did not run"]

    results = [r for r in data.get("results") or [] if isinstance(r, dict)]
    completed = sum(1 for r in results if r.get("complete") is True)
    stopped = sum(
        1 for r in results
        if r.get("timed_out") is True and r.get("stopped_at_budget_end") is True
    )
    timed_out = sum(1 for r in results if r.get("timed_out") is True) - stopped
    by_user = sum(
        1 for r in results
        if r.get("stopped_by_user") is True and r.get("complete") is not True
    )
    failed = len(results) - completed - timed_out - stopped - by_user
    retried = sum(1 for r in results if r.get("retried_alone") is True)
    too_big = sum(1 for r in results if r.get("needs_more_memory") is True)
    plain = sum(1 for r in results if r.get("mode") == "plain")
    unique = data.get("unique_eligible_files", data.get("eligible_files", 0))
    cached = sum(1 for r in results if r.get("cached_from"))
    counts = [
        f"{unique} unique",
        f"{len(results) - cached} analyzed",
        *([f"{cached} reused from cache"] if cached else []),
        f"{completed - cached} completed",
        f"{timed_out} timed out",
    ]
    if stopped:
        counts.append(f"{stopped} stopped at budget end")
    if by_user:
        counts.append(f"{by_user} stopped by you")
    if failed:
        counts.append(f"{failed} failed")
    if retried:
        counts.append(f"{retried} retried alone")
    if too_big:
        counts.append(f"{too_big} need more memory")
    if plain:
        counts.append(f"{plain} plain strings only")
    not_reached = data.get("skipped_due_to_timeout") or 0
    if not_reached:
        counts.append(f"{not_reached} not reached")
    capped = data.get("skipped_due_to_limit") or 0
    if capped:
        counts.append(f"{capped} over file cap")
    oversized = data.get("skipped_due_to_size") or 0
    if oversized:
        counts.append(f"{oversized} over size limit (n/a)")
    lines = [f"{name}: " + " · ".join(counts)]

    positioned = [r for r in results if isinstance(r.get("analysis_position"), int)]
    if positioned:
        lines.append("  order analyzed (time, peak memory):")
        ordered = sorted(positioned, key=lambda r: r["analysis_position"])
    else:
        lines.append("  results (order not recorded):")
        ordered = results
    for result in ordered[:MAX_ORDER_LINES]:
        position = result.get("analysis_position")
        if result.get("complete"):
            status = "completed"
        elif result.get("stopped_by_user"):
            status = "stopped"
        elif result.get("timed_out") and result.get("stopped_at_budget_end"):
            status = "stopped"
        elif result.get("timed_out"):
            status = "timed out"
        else:
            status = "failed"
        seconds = _number(result.get("duration_seconds")) or 0.0
        limit = _number(result.get("timeout_seconds"))
        notes = []
        if limit is not None and status != "completed":
            notes.append(f"limit {format_duration(limit)}")
        if status == "stopped" and result.get("stopped_by_user"):
            notes.append("stopped by you")
        elif status == "stopped":
            notes.append("budget ran out")
        if result.get("cached_from"):
            notes.append("reused from cache")
        if result.get("mode") == "plain":
            kept = result.get("strings")
            notes.append(
                "plain strings only"
                + (f"; {len(kept)} worth a look" if isinstance(kept, list) else "")
            )
        if result.get("needs_more_memory"):
            notes.append("needs more memory than this profile")
        elif result.get("retried_alone"):
            notes.append("retried alone after running out of memory")
        elif status == "failed" and result.get("return_code") in (-9, 137):
            notes.append("out of memory")
        note = f"  ({'; '.join(notes)})" if notes else ""
        peak = _number(result.get("peak_memory_mib"))
        shown_peak = f"{peak / 1024:.1f} GiB" if peak is not None else ""
        lines.append(
            f"  {position if position is not None else '-':>4}  "
            f"{status:<9}  {format_duration(seconds):>12}  "
            f"{shown_peak:>8}  "
            f"{clean(result.get('relative_path', '?'))}{note}"
        )
    if len(ordered) > MAX_ORDER_LINES:
        lines.append(f"  … and {len(ordered) - MAX_ORDER_LINES} more")
    return lines


def coverage_line(data: object) -> str:
    if not isinstance(data, dict):
        return "not recorded (older case)"
    try:
        return clean(headline(data), 120)
    except (TypeError, ValueError, KeyError):
        return "not readable"


def coverage_gap_lines(data: object) -> list[str]:
    if not isinstance(data, dict):
        return []
    gaps = [g for g in data.get("gaps") or [] if isinstance(g, dict)]
    if not gaps:
        return []
    lines = ["", "Not fully checked:"]
    for gap in gaps[:MAX_GAP_LINES]:
        status = clean(gap.get("status", "?"), 20).replace("_", " ")
        reason = gap.get("reason")
        lines.append(
            f"  {clean(gap.get('relative_path', '?'), 80)}  "
            f"{clean(gap.get('analyzer', '?'), 12)} {status}"
            + (f": {clean(reason, 90)}" if reason else "")
        )
    total = data.get("gap_count", len(gaps))
    if isinstance(total, int) and total > MAX_GAP_LINES:
        lines.append(f"  … and {total - MAX_GAP_LINES:,} more (see report.json)")
    return lines


def integrity_line(data: object) -> str:
    if not isinstance(data, dict):
        return "not re-checked (older case)"
    checked = data.get("checked")
    changed = data.get("changed_count") or 0
    unreadable = data.get("unreadable_count") or 0
    if data.get("skipped"):
        return f"re-check stopped early ({checked} checked)"
    if changed or unreadable:
        parts = []
        if changed:
            parts.append(f"{changed} CHANGED during the scan")
        if unreadable:
            parts.append(f"{unreadable} unreadable")
        return f"re-checked {checked}: " + ", ".join(parts)
    return f"all {checked:,} re-checked after analysis, none changed" if isinstance(checked, int) else "re-checked"


def capa_combination_lines(data: object) -> list[str]:
    """Suspicious capa combinations, worked out again from each file's capabilities.

    Re-deriving them means older cases are judged by the current policy too.
    """

    if not isinstance(data, dict):
        return []
    lines: list[str] = []
    files = 0
    for result in data.get("results") or []:
        if not isinstance(result, dict) or not isinstance(result.get("capabilities"), list):
            continue
        capabilities = [
            (item["name"], item.get("namespace"), [a for a in item.get("attack_ids") or [] if isinstance(a, str)])
            for item in result["capabilities"]
            if isinstance(item, dict) and isinstance(item.get("name"), str)
            and (item.get("namespace") is None or isinstance(item.get("namespace"), str))
        ]
        found = find_combinations(capabilities)
        if not found:
            continue
        files += 1
        path = clean(result.get("relative_path", "?"), 80)
        copies = len(result.get("reused_for") or [])
        lines.append(f"  {path}" + (f"  (+{copies} identical copies)" if copies else ""))
        for combo in found:
            lines.append(f"    - {clean(combo.description, 120)}")
            lines.append(f"      ({clean(', '.join(combo.capabilities), 160)})")
    if not files:
        return [f"capa combinations: none (policy {RISK_POLICY_VERSION})"]
    return [
        f"capa combinations: {files} {'file' if files == 1 else 'files'} "
        f"(SUSPICIOUS CAPABILITIES, policy {RISK_POLICY_VERSION}):",
        *lines,
    ]


def summarize(case: Path) -> str:
    report = load_report(case)
    status = clean(report.get("status", "unknown"), 40).replace("_", " ").title()
    summary = report.get("summary") or {}
    files = summary.get("regular_files", "?")
    size = summary.get("total_bytes")
    analyzers = report.get("analyzers") or {}
    clamav = analyzers.get("clamav") or {}
    findings = clamav.get("findings") or []
    lines = [
        f"Case     {clean(case.name)}  ({status})",
        f"Files    {files} files, {format_size(size)}",
        f"Coverage {coverage_line(report.get('coverage'))}",
        f"Profile  {profile_line(report)}",
        f"Timings  {timings_line(report)}",
        f"ClamAV   {clean(clamav.get('status', 'not recorded'), 20)}"
        + (f" · {len(findings)} detection(s)" if findings else ""),
        f"YARA-X   {yara_line(analyzers.get('yara'))}",
        f"Hashes   {integrity_line(report.get('integrity'))}",
        "",
        *analyzer_lines("capa", analyzers.get("capa")),
        *capa_combination_lines(analyzers.get("capa")),
        "",
        *analyzer_lines("FLOSS", analyzers.get("floss")),
    ]
    warnings = [w for w in report.get("warnings") or [] if isinstance(w, str)]
    if any("stopped by the user" in w for w in warnings):
        lines += ["", "Stopped  by you before it finished; this covers the work done by then."]
    lines += coverage_gap_lines(report.get("coverage"))
    reasons = report.get("incomplete_reasons") or []
    if reasons:
        lines += ["", "Coverage gaps:"]
        lines += [f"  - {clean(reason)}" for reason in reasons]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args and args[0] in {"-h", "--help"}:
        print(
            "usage: summary.sh [CASE_FOLDER | RESULTS_FOLDER]\n"
            "Prints a short summary of a saved case. With no argument, "
            "shows the newest case in ~/mantha-ray-results."
        )
        return 0
    target = Path(args[0]) if args else DEFAULT_RESULTS
    print(summarize(find_case(target)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())