from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from .file_progress import format_duration, format_size

DEFAULT_RESULTS = Path.home() / "mantha-ray-results"
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_ORDER_LINES = 40

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
    for stage in ("inventory", "clamav", "capa", "floss"):
        record = timings.get(stage)
        if not isinstance(record, dict):
            continue
        seconds = _number(record.get("duration_seconds"))
        shown = format_duration(seconds) if seconds is not None else "—"
        parts.append(f"{stage} {shown}")
    return " · ".join(parts)


def analyzer_lines(name: str, data: object) -> list[str]:
    if not isinstance(data, dict):
        return [f"{name}: not recorded"]
    if data.get("status") == "not_run":
        return [f"{name}: did not run"]

    results = [r for r in data.get("results") or [] if isinstance(r, dict)]
    completed = sum(1 for r in results if r.get("complete") is True)
    timed_out = sum(1 for r in results if r.get("timed_out") is True)
    failed = len(results) - completed - timed_out
    unique = data.get("unique_eligible_files", data.get("eligible_files", 0))
    counts = [
        f"{unique} unique",
        f"{len(results)} analyzed",
        f"{completed} completed",
        f"{timed_out} timed out",
    ]
    if failed:
        counts.append(f"{failed} failed")
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
        lines.append("  order analyzed:")
        ordered = sorted(positioned, key=lambda r: r["analysis_position"])
    else:
        lines.append("  results (order not recorded):")
        ordered = results
    for result in ordered[:MAX_ORDER_LINES]:
        position = result.get("analysis_position")
        status = "completed" if result.get("complete") else (
            "timed out" if result.get("timed_out") else "failed"
        )
        seconds = _number(result.get("duration_seconds")) or 0.0
        lines.append(
            f"  {position if position is not None else '-':>4}  "
            f"{status:<9}  {format_duration(seconds):>12}  "
            f"{clean(result.get('relative_path', '?'))}"
        )
    if len(ordered) > MAX_ORDER_LINES:
        lines.append(f"  … and {len(ordered) - MAX_ORDER_LINES} more")
    return lines


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
        f"Profile  {profile_line(report)}",
        f"Timings  {timings_line(report)}",
        f"ClamAV   {clean(clamav.get('status', 'not recorded'), 20)}"
        + (f" · {len(findings)} detection(s)" if findings else ""),
        "",
        *analyzer_lines("capa", analyzers.get("capa")),
        "",
        *analyzer_lines("FLOSS", analyzers.get("floss")),
    ]
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