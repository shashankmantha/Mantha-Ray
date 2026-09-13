from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from static_triage.capa import (
    CapaBatchResult,
    CapaBatchStatus,
    CapaResult,
    CapaStatus,
)
from static_triage.clamav import (
    ClamAVResult,
    ClamAVStatus,
)
from static_triage.config import ScanConfig
from static_triage.floss import (
    FlossBatchResult,
    FlossBatchStatus,
    FlossResult,
    FlossStatus,
    FlossString,
)
from static_triage.models import ToolInfo
from static_triage.scanner import run_inventory_scan


def minimal_pe() -> bytes:
    """Create a harmless synthetic PE fixture."""

    data = bytearray(256)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (128).to_bytes(
        4,
        "little",
    )

    data[128:132] = b"PE\x00\x00"
    data[150:152] = (0x0002).to_bytes(
        2,
        "little",
    )

    return bytes(data)


def available_tools() -> list[ToolInfo]:
    """Return synthetic available analyzer tools."""

    return [
        ToolInfo(
            name="clamscan",
            executable="/usr/bin/clamscan",
            available=True,
            version="ClamAV test",
            error=None,
        ),
        ToolInfo(
            name="capa",
            executable="/usr/local/bin/capa",
            available=True,
            version="capa test",
            error=None,
        ),
        ToolInfo(
            name="floss",
            executable="/usr/local/bin/floss",
            available=True,
            version="FLOSS test",
            error=None,
        ),
    ]


def clean_clamav_result() -> ClamAVResult:
    """Return a complete synthetic clean result."""

    return ClamAVResult(
        status=ClamAVStatus.CLEAN,
        complete=True,
        return_code=0,
        findings=(),
        timed_out=False,
        output_truncated=False,
        duration_seconds=0.1,
        stdout="Infected files: 0\n",
        stderr="",
        error=None,
    )


def completed_capa_result() -> CapaBatchResult:
    """Return a complete capa result with no matches."""

    file_result = CapaResult(
        status=CapaStatus.COMPLETED,
        complete=True,
        relative_path="sample.exe",
        return_code=0,
        capabilities=(),
        timed_out=False,
        output_truncated=False,
        duration_seconds=0.1,
        stdout='{"rules": {}}',
        stderr="",
        error=None,
    )

    return CapaBatchResult(
        status=CapaBatchStatus.COMPLETED,
        complete=True,
        eligible_files=1,
        attempted_files=1,
        skipped_due_to_limit=0,
        skipped_due_to_timeout=0,
        results=(file_result,),
        duration_seconds=0.1,
        error=None,
    )


def completed_floss_result(
    *,
    include_string: bool,
) -> FlossBatchResult:
    """Return a complete synthetic FLOSS batch."""

    strings = (
        (
            FlossString(
                kind="decoded",
                value="https://example.invalid/beacon",
                encoding="ASCII",
                truncated=False,
            ),
        )
        if include_string
        else ()
    )

    file_result = FlossResult(
        status=FlossStatus.COMPLETED,
        complete=True,
        relative_path="sample.exe",
        return_code=0,
        strings=strings,
        total_strings=len(strings),
        strings_truncated=False,
        timed_out=False,
        output_truncated=False,
        duration_seconds=0.1,
        stdout=json.dumps(
            {
                "strings": {
                    "decoded_strings": [
                        item.to_dict()
                        for item in strings
                    ],
                }
            }
        ),
        stderr="",
        error=None,
    )

    return FlossBatchResult(
        status=FlossBatchStatus.COMPLETED,
        complete=True,
        eligible_files=1,
        attempted_files=1,
        skipped_due_to_limit=0,
        skipped_due_to_timeout=0,
        results=(file_result,),
        duration_seconds=0.1,
        error=None,
    )


class FlossEndToEndTests(unittest.TestCase):
    def test_floss_strings_are_reported_and_written(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            sample = base / "staging" / "sample"
            sample.mkdir(parents=True)

            input_file = sample / "sample.exe"
            original = minimal_pe()
            input_file.write_bytes(original)

            floss_batch = completed_floss_result(
                include_string=True
            )

            with patch(
                "static_triage.scanner.inspect_tools",
                return_value=available_tools(),
            ):
                with patch(
                    "static_triage.scanner.run_clamav",
                    return_value=clean_clamav_result(),
                ):
                    with patch(
                        "static_triage.scanner.run_capa_batch",
                        return_value=completed_capa_result(),
                    ):
                        with patch(
                            "static_triage.scanner.run_floss_batch",
                            return_value=floss_batch,
                        ) as mocked_floss:
                            result = run_inventory_scan(
                                "sample",
                                ScanConfig(
                                    staging_root=(
                                        base / "staging"
                                    ),
                                    results_root=(
                                        base / "results"
                                    ),
                                ),
                            )

            self.assertEqual(
                input_file.read_bytes(),
                original,
            )

            mocked_floss.assert_called_once()

            report = json.loads(
                (
                    result.case_directory
                    / "report.json"
                ).read_text(encoding="utf-8")
            )

            self.assertEqual(
                report["status"],
                "needs_review",
            )

            floss_report = report[
                "analyzers"
            ]["floss"]

            self.assertTrue(
                floss_report["complete"]
            )

            self.assertEqual(
                floss_report[
                    "extracted_string_count"
                ],
                1,
            )

            self.assertEqual(
                floss_report["results"][0]
                ["strings"][0]["value"],
                "https://example.invalid/beacon",
            )

            floss_raw = (
                result.case_directory
                / "raw"
                / "floss"
            )

            raw_summary = json.loads(
                (
                    floss_raw / "result.json"
                ).read_text(encoding="utf-8")
            )

            self.assertEqual(
                raw_summary[
                    "extracted_string_count"
                ],
                1,
            )

            result_directories = [
                path
                for path in floss_raw.iterdir()
                if path.is_dir()
            ]

            self.assertEqual(
                len(result_directories),
                1,
            )

            self.assertTrue(
                (
                    result_directories[0]
                    / "result.json"
                ).is_file()
            )

            self.assertTrue(
                (
                    result_directories[0]
                    / "stdout.json"
                ).is_file()
            )

            self.assertTrue(
                (
                    result_directories[0]
                    / "stderr.txt"
                ).is_file()
            )

            markdown = (
                result.case_directory
                / "report.md"
            ).read_text(encoding="utf-8")

            self.assertIn(
                "Needs Review",
                markdown,
            )

            self.assertIn(
                "## FLOSS analysis",
                markdown,
            )

            self.assertIn(
                "https://example.invalid/beacon",
                markdown,
            )

    def test_complete_empty_results_have_no_indicators(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            sample = base / "staging" / "sample"
            sample.mkdir(parents=True)

            (sample / "sample.exe").write_bytes(
                minimal_pe()
            )

            with patch(
                "static_triage.scanner.inspect_tools",
                return_value=available_tools(),
            ):
                with patch(
                    "static_triage.scanner.run_clamav",
                    return_value=clean_clamav_result(),
                ):
                    with patch(
                        "static_triage.scanner.run_capa_batch",
                        return_value=completed_capa_result(),
                    ):
                        with patch(
                            "static_triage.scanner.run_floss_batch",
                            return_value=(
                                completed_floss_result(
                                    include_string=False
                                )
                            ),
                        ):
                            result = run_inventory_scan(
                                "sample",
                                ScanConfig(
                                    staging_root=(
                                        base / "staging"
                                    ),
                                    results_root=(
                                        base / "results"
                                    ),
                                ),
                            )

            report = json.loads(
                (
                    result.case_directory
                    / "report.json"
                ).read_text(encoding="utf-8")
            )

            self.assertEqual(
                report["status"],
                "no_indicators_detected",
            )

            self.assertEqual(
                report["incomplete_reasons"],
                [],
            )

            markdown = (
                result.case_directory
                / "report.md"
            ).read_text(encoding="utf-8")

            self.assertIn(
                "No Indicators Detected",
                markdown,
            )

            self.assertIn(
                "All configured inventory and "
                "analyzer stages completed.",
                markdown,
            )


if __name__ == "__main__":
    unittest.main()