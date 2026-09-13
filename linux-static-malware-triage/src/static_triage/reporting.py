"""Deterministic JSON, JSONL, Markdown, and log reporting."""

from __future__ import annotations

import json
import hashlib
import os

from .capa import CapaBatchResult
from dataclasses import asdict
from pathlib import Path
from typing import Any
from .clamav import ClamAVResult, ClamAVStatus
from .floss import FlossBatchResult

from . import __version__
from .config import ScanConfig
from .models import (
    EntryState,
    InventoryEntry,
    InventorySummary,
    OverallStatus,
    RoutingClass,
    SCHEMA_VERSION,
    ToolInfo,
)


def _write_json(path: Path, payload: Any) -> None:
    """Write stable, human-readable JSON."""

    path.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


def _bounded_text(
    value: object,
    max_chars: int = 500,
) -> str:
    """Bound and escape control characters in untrusted text."""

    text = (
        str(value)
        .replace("\x00", "\\0")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )

    if len(text) <= max_chars:
        return text

    return text[: max_chars - 1] + "…"


def _markdown_code(value: object) -> str:
    """Safely place untrusted text inside a Markdown code span."""

    text = json.dumps(
        _bounded_text(value),
        ensure_ascii=False,
    )

    longest_run = 0
    current_run = 0

    for character in text:
        if character == "`":
            current_run += 1
            longest_run = max(longest_run, current_run)
        else:
            current_run = 0

    fence = "`" * (longest_run + 1)

    return f"{fence} {text} {fence}"

def _determine_status(
    clamav_result: ClamAVResult | None,
    capa_result: CapaBatchResult | None,
    floss_result: FlossBatchResult | None,
    summary: InventorySummary,
) -> OverallStatus:
    """Calculate the strongest supported case status."""

    if (
        clamav_result is not None
        and clamav_result.status
        == ClamAVStatus.INFECTED
    ):
        return OverallStatus.KNOWN_DETECTION

    analyzers_complete = (
        clamav_result is not None
        and clamav_result.complete
        and capa_result is not None
        and capa_result.complete
        and floss_result is not None
        and floss_result.complete
    )

    inventory_complete = (
        summary.errors == 0
        and summary.limit_exceeded == 0
    )

    if not analyzers_complete or not inventory_complete:
        return OverallStatus.INCOMPLETE

    capa_evidence = any(
        result.capabilities
        for result in capa_result.results
    )

    floss_evidence = any(
        result.strings
        for result in floss_result.results
    )

    if (
        summary.review_flags
        or capa_evidence
        or floss_evidence
    ):
        return OverallStatus.NEEDS_REVIEW

    return OverallStatus.NO_INDICATORS_DETECTED

def write_case_artifacts(
    case_directory: Path,
    case_id: str,
    started_at: str,
    completed_at: str,
    target_relative: str,
    config: ScanConfig,
    entries: list[InventoryEntry],
    summary: InventorySummary,
    tools: list[ToolInfo],
    clamav_result: ClamAVResult | None,
    warnings: list[str],
    capa_result: CapaBatchResult | None = None,
    floss_result: FlossBatchResult | None = None,
) -> dict[str, Any]:
    """Write the complete inventory-milestone artifact set."""

    case_directory.mkdir(
        parents=True,
        exist_ok=False,
    )

    capa_raw_directory = (
        case_directory
        / "raw"
        / "capa"
    )

    capa_raw_directory.mkdir(parents=True)


    floss_raw_directory = (
        case_directory
        / "raw"
        / "floss"
    )

    floss_raw_directory.mkdir(parents=True)

    clamav_raw_directory = (
        case_directory
        / "raw"
        / "clamav"
    )

    clamav_raw_directory.mkdir(parents=True)

    (case_directory / "logs").mkdir(
        parents=True
    )

    unavailable_tools = [
        tool.name
        for tool in tools
        if not tool.available
    ]

    incomplete_reasons: list[str] = []

    if clamav_result is None:
        incomplete_reasons.append(
            "ClamAV did not run"
        )
    elif not clamav_result.complete:
        incomplete_reasons.append(
            "ClamAV analysis was incomplete"
        )

    if capa_result is None:
        incomplete_reasons.append(
            "capa did not run"
        )
    elif not capa_result.complete:
        incomplete_reasons.append(
            "capa analysis was incomplete"
        )

    if floss_result is None:
        incomplete_reasons.append(
            "FLOSS did not run"
        )
    elif not floss_result.complete:
        incomplete_reasons.append(
            "FLOSS analysis was incomplete"
        )

    if clamav_result is None:
        clamav_payload: dict[str, Any] = {
            "status": "not_run",
            "complete": False,
            "return_code": None,
            "findings": [],
            "timed_out": False,
            "output_truncated": False,
            "duration_seconds": None,
            "error": "ClamAV was unavailable",
        }
    else:
        clamav_payload = clamav_result.to_dict()

    if capa_result is None:
        capa_payload: dict[str, Any] = {
            "status": "not_run",
            "complete": False,
            "eligible_files": (
                summary.supported_binaries
            ),
            "attempted_files": 0,
            "skipped_due_to_limit": 0,
            "skipped_due_to_timeout": 0,
            "capability_count": 0,
            "results": [],
            "duration_seconds": None,
            "error": "capa was unavailable",
        }
    else:
        capa_payload = capa_result.to_dict()

    floss_eligible_files = sum(
        entry.state == EntryState.INVENTORIED
        and entry.routing_class
        in {
            RoutingClass.PE_EXECUTABLE,
            RoutingClass.PE_DLL,
        }
        for entry in entries
    )

    if floss_result is None:
        floss_payload: dict[str, Any] = {
            "status": "not_run",
            "complete": False,
            "eligible_files": floss_eligible_files,
            "attempted_files": 0,
            "skipped_due_to_limit": 0,
            "skipped_due_to_timeout": 0,
            "extracted_string_count": 0,
            "total_string_count": 0,
            "strings_truncated": False,
            "results": [],
            "duration_seconds": None,
            "error": "FLOSS was unavailable",
        }
    else:
        floss_payload = floss_result.to_dict()

    if unavailable_tools:
        incomplete_reasons.append(
            "tools unavailable during preflight: "
            + ", ".join(unavailable_tools)
        )

    if summary.errors or summary.limit_exceeded:
        incomplete_reasons.append(
            "one or more entries could not be "
            "completely inventoried"
        )

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "scanner_version": __version__,
        "started_at": started_at,
        "completed_at": completed_at,
        "target": target_relative,
        "limits": asdict(config.limits),
        "tools": [
            tool.to_dict()
            for tool in tools
        ],
        "analyzers": {
            "clamav": clamav_payload,
            "capa": capa_payload,
            "floss": floss_payload,
        },
    }

    overall_status = _determine_status(
        clamav_result,
        capa_result,
        floss_result,
        summary,
    )

    report = {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "status": overall_status.value,
        "uncertainty": (
            "Static inventory and hashes do not prove "
            "that files are safe."
        ),
        "summary": summary.to_dict(),
        "warnings": warnings,
        "incomplete_reasons": incomplete_reasons,
        "review_items": [
            entry.to_dict()
            for entry in entries
            if (
                entry.evidence
                or entry.state != EntryState.INVENTORIED
            )
        ],
        "recommended_next_steps": [
            (
                "Review signature matches, capability "
                "matches, extracted strings, and "
                "inventory flags."
            ),
            (
                "Repeat any analyzer stage reported as "
                "incomplete before reaching a conclusion."
            ),
            (
                "Do not execute samples based only on "
                "the absence of static indicators."
            ),
        ],
        "analyzers": {
            "clamav": clamav_payload,
            "capa": capa_payload,
            "floss": floss_payload,
        },
    }

    _write_json(
        case_directory / "manifest.json",
        manifest,
    )

    _write_json(
        case_directory / "report.json",
        report,
    )

    with (
        case_directory / "files.jsonl"
    ).open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:
        for entry in entries:
            handle.write(
                json.dumps(
                    entry.to_dict(),
                    sort_keys=True,
                    ensure_ascii=False,
                )
                + "\n"
            )

    markdown = _render_markdown(report)

    (case_directory / "report.md").write_text(
        markdown,
        encoding="utf-8",
    )

    (
        case_directory
        / "logs"
        / "scanner.log"
    ).write_text(
        (
            f"{completed_at} "
            f"case={case_id} "
            "inventory_complete "
            f"files={summary.regular_files} "
            f"hashed={summary.hashed_files}\n"
        ),
        encoding="utf-8",
    )

    _write_json(
        clamav_raw_directory / "result.json",
        clamav_payload,
    )

    (
        clamav_raw_directory
        / "stdout.txt"
    ).write_text(
        (
            clamav_result.stdout
            if clamav_result is not None
            else ""
        ),
        encoding="utf-8",
    )

    (
        clamav_raw_directory
        / "stderr.txt"
    ).write_text(
        (
            clamav_result.stderr
            if clamav_result is not None
            else ""
        ),
        encoding="utf-8",
    )

    _write_json(
        capa_raw_directory / "result.json",
        capa_payload,
    )

    if capa_result is not None:
        for index, result in enumerate(
            capa_result.results,
            start=1,
        ):
            path_identifier = hashlib.sha256(
                os.fsencode(result.relative_path)
            ).hexdigest()[:16]

            result_directory = (
                capa_raw_directory
                / (
                    f"{index:04d}-"
                    f"{path_identifier}"
                )
            )

            result_directory.mkdir()

            _write_json(
                result_directory / "result.json",
                result.to_dict(),
            )

            (
                result_directory
                / "stdout.json"
            ).write_text(
                result.stdout,
                encoding="utf-8",
            )

            (
                result_directory
                / "stderr.txt"
            ).write_text(
                result.stderr,
                encoding="utf-8",
            )

    _write_json(
        floss_raw_directory / "result.json",
        floss_payload,
    )

    if floss_result is not None:
        for index, result in enumerate(
            floss_result.results,
            start=1,
        ):
            path_identifier = hashlib.sha256(
                os.fsencode(result.relative_path)
            ).hexdigest()[:16]

            result_directory = (
                floss_raw_directory
                / (
                    f"{index:04d}-"
                    f"{path_identifier}"
                )
            )

            result_directory.mkdir()

            _write_json(
                result_directory / "result.json",
                result.to_dict(),
            )

            (
                result_directory
                / "stdout.json"
            ).write_text(
                result.stdout,
                encoding="utf-8",
            )

            (
                result_directory
                / "stderr.txt"
            ).write_text(
                result.stderr,
                encoding="utf-8",
            )

    return report


def _render_markdown(
    report: dict[str, Any],
) -> str:
    """Render the normalized report using fixed text."""

    summary = report["summary"]

    lines = [
        "# Static malware triage report",
        "",
        f"- Case: `{report['case_id']}`",
        (
            "- Status: **"
            + report["status"]
            .replace("_", " ")
            .title()
            + "**"
        ),
        f"- Uncertainty: {report['uncertainty']}",
        "",
        "## Inventory summary",
        "",
        "| Measure | Count |",
        "| --- | ---: |",
    ]

    summary_fields = (
        ("Regular files", "regular_files"),
        ("Files hashed", "hashed_files"),
        ("Total bytes", "total_bytes"),
        ("Supported binaries", "supported_binaries"),
        ("Review flags", "review_flags"),
        ("Skipped entries", "skipped_entries"),
        ("Errors", "errors"),
        ("Limit exceeded", "limit_exceeded"),
    )

    for label, key in summary_fields:
        lines.append(
            f"| {label} | {summary[key]} |"
        )

    clamav = report["analyzers"]["clamav"]

    lines.extend(
        [
            "",
            "## ClamAV analysis",
            "",
            (
                "- Status: **"
                + clamav["status"]
                .replace("_", " ")
                .title()
                + "**"
            ),
            f"- Complete: `{clamav['complete']}`",
        ]
    )

    if clamav.get("error"):
        lines.append(
            "- Error: "
            + _markdown_code(clamav["error"])
        )

    clamav_findings = (
        clamav.get("findings") or []
    )

    if clamav_findings:
        lines.extend(
            [
                "",
                "### Signature matches",
                "",
            ]
        )

        for finding in clamav_findings[:100]:
            lines.append(
                "- "
                + _markdown_code(
                    finding["relative_path"]
                )
                + " — "
                + _markdown_code(
                    finding["signature"]
                )
            )

        if len(clamav_findings) > 100:
            remaining = (
                len(clamav_findings) - 100
            )

            lines.append(
                f"- {remaining} additional ClamAV "
                "findings are available in "
                "`report.json`."
            )

    elif clamav["status"] == "clean":
        lines.extend(
            [
                "",
                (
                    "No ClamAV signature matches "
                    "were reported."
                ),
            ]
        )

    else:
        lines.extend(
            [
                "",
                "ClamAV did not complete a clean scan.",
            ]
        )

    capa = report["analyzers"]["capa"]

    lines.extend(
        [
            "",
            "## capa analysis",
            "",
            (
                "- Status: **"
                + capa["status"]
                .replace("_", " ")
                .title()
                + "**"
            ),
            f"- Complete: `{capa['complete']}`",
            (
                "- Eligible binaries: "
                f"`{capa['eligible_files']}`"
            ),
            (
                "- Attempted binaries: "
                f"`{capa['attempted_files']}`"
            ),
            (
                "- Skipped by file limit: "
                f"`{capa['skipped_due_to_limit']}`"
            ),
            (
                "- Skipped by time limit: "
                f"`{capa['skipped_due_to_timeout']}`"
            ),
            (
                "- Capability matches: "
                f"`{capa['capability_count']}`"
            ),
        ]
    )

    if capa.get("error"):
        lines.append(
            "- Error: "
            + _markdown_code(capa["error"])
        )

    capa_results = capa.get("results") or []
    rendered_capabilities = 0

    for result in capa_results:
        capabilities = (
            result.get("capabilities") or []
        )

        if (
            capabilities
            and rendered_capabilities == 0
        ):
            lines.extend(
                [
                    "",
                    "### Capability matches",
                    "",
                ]
            )

        for capability in capabilities:
            if rendered_capabilities >= 100:
                break

            details = [
                (
                    "matches="
                    + str(capability["match_count"])
                )
            ]

            namespace = capability.get(
                "namespace"
            )

            if namespace:
                details.append(
                    "namespace="
                    + _bounded_text(namespace)
                )

            attack_ids = (
                capability.get("attack_ids")
                or []
            )

            if attack_ids:
                details.append(
                    "ATT&CK="
                    + ", ".join(
                        _bounded_text(item)
                        for item in attack_ids
                    )
                )

            mbc_ids = (
                capability.get("mbc_ids")
                or []
            )

            if mbc_ids:
                details.append(
                    "MBC="
                    + ", ".join(
                        _bounded_text(item)
                        for item in mbc_ids
                    )
                )

            lines.append(
                "- "
                + _markdown_code(
                    result["relative_path"]
                )
                + " — "
                + _markdown_code(
                    capability["name"]
                )
                + " — "
                + _markdown_code(
                    "; ".join(details)
                )
            )

            rendered_capabilities += 1

        if rendered_capabilities >= 100:
            break

    total_capabilities = capa["capability_count"]

    if total_capabilities > rendered_capabilities:
        remaining = (
            total_capabilities
            - rendered_capabilities
        )

        lines.append(
            f"- {remaining} additional capa "
            "capabilities are available in "
            "`report.json`."
        )

    if rendered_capabilities == 0:
        lines.append("")

        if capa["eligible_files"] == 0:
            lines.append(
                "No inventory-approved PE or ELF "
                "binaries were eligible for capa."
            )
        elif capa["status"] == "completed":
            lines.append(
                "capa completed without reporting "
                "capability matches."
            )
        else:
            lines.append(
                "capa did not complete capability "
                "analysis."
            )


    floss = report["analyzers"]["floss"]


    lines.extend(
        [
            "",
            "## FLOSS analysis",
            "",
            (
                "- Status: **"
                + floss["status"]
                .replace("_", " ")
                .title()
                + "**"
            ),
            f"- Complete: `{floss['complete']}`",
            (
                "- Eligible PE files: "
                f"`{floss['eligible_files']}`"
            ),
            (
                "- Attempted PE files: "
                f"`{floss['attempted_files']}`"
            ),
            (
                "- Skipped by file limit: "
                f"`{floss['skipped_due_to_limit']}`"
            ),
            (
                "- Skipped by time limit: "
                f"`{floss['skipped_due_to_timeout']}`"
            ),
            (
                "- Stored extracted strings: "
                f"`{floss['extracted_string_count']}`"
            ),
            (
                "- Total strings observed: "
                f"`{floss['total_string_count']}`"
            ),
            (
                "- String results truncated: "
                f"`{floss['strings_truncated']}`"
            ),
        ]
    )

    if floss.get("error"):
        lines.append(
            "- Error: "
            + _markdown_code(floss["error"])
        )

    floss_results = floss.get("results") or []
    rendered_strings = 0

    for result in floss_results:
        extracted_strings = (
            result.get("strings") or []
        )

        if (
            extracted_strings
            and rendered_strings == 0
        ):
            lines.extend(
                [
                    "",
                    "### Extracted strings",
                    "",
                ]
            )

        for item in extracted_strings:
            if rendered_strings >= 100:
                break

            details = [
                "kind="
                + _bounded_text(item["kind"])
            ]

            encoding = item.get("encoding")

            if encoding:
                details.append(
                    "encoding="
                    + _bounded_text(encoding)
                )

            if item.get("truncated"):
                details.append(
                    "value truncated"
                )

            lines.append(
                "- "
                + _markdown_code(
                    result["relative_path"]
                )
                + " — "
                + _markdown_code(item["value"])
                + " — "
                + _markdown_code(
                    "; ".join(details)
                )
            )

            rendered_strings += 1

        if rendered_strings >= 100:
            break

    stored_strings = floss[
        "extracted_string_count"
    ]

    if stored_strings > rendered_strings:
        remaining = (
            stored_strings - rendered_strings
        )

        lines.append(
            f"- {remaining} additional normalized "
            "FLOSS strings are available in "
            "`report.json`."
        )

    total_strings = floss["total_string_count"]

    if total_strings > stored_strings:
        omitted = total_strings - stored_strings

        lines.append(
            f"- {omitted} additional strings exceeded "
            "the normalized result limit; inspect the "
            "bounded raw FLOSS JSON."
        )

    if rendered_strings == 0:
        lines.append("")

        if floss["eligible_files"] == 0:
            lines.append(
                "No inventory-approved PE files were "
                "eligible for FLOSS."
            )
        elif floss["status"] == "completed":
            lines.append(
                "FLOSS completed without extracting "
                "non-static strings."
            )
        else:
            lines.append(
                "FLOSS did not complete string "
                "analysis."
            )

            
    incomplete_reasons = report[
        "incomplete_reasons"
    ]

    if incomplete_reasons:
        lines.extend(
            [
                "",
                (
                    "## Coverage gaps and "
                    "incomplete stages"
                ),
                "",
            ]
        )

        lines.extend(
            f"- {reason}"
            for reason in incomplete_reasons
        )
    else:
        lines.extend(
            [
                "",
                "## Coverage",
                "",
                (
                    "All configured inventory and "
                    "analyzer stages completed."
                ),
            ]
        )


    lines.extend(
        [
            "",
            "## Prioritized review items",
            "",
        ]
    )

    review_items = report["review_items"]

    if not review_items:
        lines.append(
            "No inventory-stage review flags "
            "were recorded."
        )

    for item in review_items[:100]:
        safe_path = _markdown_code(
            item["relative_path"]
        )

        evidence = _bounded_text(
            "; ".join(
                item.get("evidence") or []
            )
            or item.get("error")
            or item["state"]
        )

        lines.append(
            f"- {safe_path} — {evidence}"
        )

    if len(review_items) > 100:
        remaining = len(review_items) - 100

        lines.append(
            f"- {remaining} additional review "
            "items are available in "
            "`report.json`."
        )

    lines.extend(
        [
            "",
            "## Recommended next steps",
            "",
        ]
    )

    lines.extend(
        f"- {item}"
        for item in report[
            "recommended_next_steps"
        ]
    )

    lines.append("")

    return "\n".join(lines)