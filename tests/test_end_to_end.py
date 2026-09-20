from __future__ import annotations

import json
import tempfile
import unittest
import hashlib
import os

from pathlib import Path
from unittest.mock import patch

from static_triage.clamav import (
    ClamAVFinding,
    ClamAVResult,
    ClamAVStatus,
)
from static_triage.config import ScanConfig
from static_triage.models import ToolInfo
from static_triage.scanner import run_inventory_scan

from static_triage.capa import (
    CapaBatchResult,
    CapaBatchStatus,
    CapaCapability,
    CapaResult,
    CapaStatus,
)


class EndToEndTests(unittest.TestCase):
    @patch(
        "static_triage.scanner.inspect_tools",
        return_value=[],
    )
    def test_scan_writes_expected_artifacts(
        self,
        _mocked_tools,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)

            sample = (
                base
                / "staging"
                / "sample"
            )

            results = base / "results"
            sample.mkdir(parents=True)

            original = b"benign fixture\n"
            input_file = sample / "readme.txt"
            input_file.write_bytes(original)

            result = run_inventory_scan(
                "sample",
                ScanConfig(
                    staging_root=base / "staging",
                    results_root=results,
                ),
            )

            # Confirm the scanner did not modify the sample.
            self.assertEqual(
                input_file.read_bytes(),
                original,
            )

            expected_entries = {
                "manifest.json",
                "report.json",
                "report.md",
                "files.jsonl",
                "raw",
                "logs",
            }

            actual_entries = {
                path.name
                for path in result.case_directory.iterdir()
            }

            self.assertEqual(
                actual_entries,
                expected_entries,
            )

            report = json.loads(
                (
                    result.case_directory
                    / "report.json"
                ).read_text(encoding="utf-8")
            )

            # Missing analyzer execution must never
            # accidentally become a clean result.
            self.assertEqual(
                report["status"],
                "incomplete",
            )

            self.assertEqual(
                report["summary"]["hashed_files"],
                1,
            )

            clamav_raw = (
                result.case_directory
                / "raw"
                / "clamav"
            )

            self.assertTrue(
                (clamav_raw / "result.json").is_file()
            )

            self.assertTrue(
                (clamav_raw / "stdout.txt").is_file()
            )

            self.assertTrue(
                (clamav_raw / "stderr.txt").is_file()
            )

    @patch(
        "static_triage.scanner.inspect_tools",
        return_value=[],
    )
    def test_report_handles_adversarial_filename(
        self,
        _mocked_tools,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)

            sample = (
                base
                / "staging"
                / "sample"
            )

            sample.mkdir(parents=True)

            suspicious_name = (
                sample
                / "odd`name.pdf.exe"
            )

            suspicious_name.write_bytes(
                b"plain text"
            )

            result = run_inventory_scan(
                "sample",
                ScanConfig(
                    staging_root=base / "staging",
                    results_root=base / "results",
                ),
            )

            markdown = (
                result.case_directory
                / "report.md"
            ).read_text(encoding="utf-8")

            self.assertIn(
                "odd`name.pdf.exe",
                markdown,
            )

            self.assertIn(
                "double-extension filename",
                markdown,
            )

    def test_clamav_detection_sets_known_detection(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)

            sample = (
                base
                / "staging"
                / "sample"
            )

            sample.mkdir(parents=True)

            infected_file = sample / "eicar.com"
            infected_file.write_bytes(
                b"safe mocked test fixture"
            )

            tool = ToolInfo(
                name="clamscan",
                executable="/usr/bin/clamscan",
                available=True,
                version="ClamAV test version",
                error=None,
            )

            clamav_result = ClamAVResult(
                status=ClamAVStatus.INFECTED,
                complete=True,
                return_code=1,
                findings=(
                    ClamAVFinding(
                        relative_path="eicar.com",
                        signature="Win.Test.EICAR_HDB-1",
                    ),
                ),
                timed_out=False,
                output_truncated=False,
                duration_seconds=0.25,
                stdout=(
                    f"{infected_file}: "
                    "Win.Test.EICAR_HDB-1 FOUND\n"
                ),
                stderr="",
                error=None,
            )

            with patch(
                "static_triage.scanner.inspect_tools",
                return_value=[tool],
            ):
                with patch(
                    "static_triage.scanner.run_clamav",
                    return_value=clamav_result,
                ) as mocked_clamav:
                    result = run_inventory_scan(
                        "sample",
                        ScanConfig(
                            staging_root=base / "staging",
                            results_root=base / "results",
                        ),
                    )

            mocked_clamav.assert_called_once_with(
                sample.resolve(),
                executable="/usr/bin/clamscan",
            )

            report = json.loads(
                (
                    result.case_directory
                    / "report.json"
                ).read_text(encoding="utf-8")
            )

            self.assertEqual(
                report["status"],
                "known_detection",
            )

            clamav_report = (
                report["analyzers"]["clamav"]
            )

            self.assertEqual(
                clamav_report["status"],
                "infected",
            )

            self.assertEqual(
                clamav_report["findings"][0]["signature"],
                "Win.Test.EICAR_HDB-1",
            )

            raw_result = json.loads(
                (
                    result.case_directory
                    / "raw"
                    / "clamav"
                    / "result.json"
                ).read_text(encoding="utf-8")
            )

            self.assertEqual(
                raw_result["status"],
                "infected",
            )

            markdown = (
                result.case_directory
                / "report.md"
            ).read_text(encoding="utf-8")

            self.assertIn(
                "Known Detection",
                markdown,
            )

            self.assertIn(
                "Win.Test.EICAR_HDB-1",
                markdown,
            )


    def test_capa_results_are_written(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)

            sample = (
                base
                / "staging"
                / "sample"
            )

            sample.mkdir(parents=True)

            # Safe synthetic PE header. It is never executed.
            payload = bytearray(256)
            payload[0:2] = b"MZ"
            payload[0x3C:0x40] = (
                128
            ).to_bytes(4, "little")
            payload[128:132] = b"PE\x00\x00"
            payload[150:152] = (
                0x0002
            ).to_bytes(2, "little")

            binary = sample / "program.exe"
            binary.write_bytes(bytes(payload))

            capa_tool = ToolInfo(
                name="capa",
                executable="/usr/local/bin/capa",
                available=True,
                version="capa test version",
                error=None,
            )

            capa_file_result = CapaResult(
                status=CapaStatus.COMPLETED,
                complete=True,
                relative_path="program.exe",
                return_code=0,
                capabilities=(
                    CapaCapability(
                        name="send HTTP request",
                        namespace=(
                            "communication/http/client"
                        ),
                        match_count=2,
                        attack_ids=("T1071.001",),
                        mbc_ids=("C0002",),
                    ),
                ),
                timed_out=False,
                output_truncated=False,
                duration_seconds=0.25,
                stdout=json.dumps(
                    {
                        "meta": {
                            "version": "test",
                        },
                        "rules": {},
                    }
                ),
                stderr="",
                error=None,
            )

            capa_batch_result = CapaBatchResult(
                status=CapaBatchStatus.COMPLETED,
                complete=True,
                eligible_files=1,
                attempted_files=1,
                skipped_due_to_limit=0,
                skipped_due_to_timeout=0,
                results=(capa_file_result,),
                duration_seconds=0.25,
                error=None,
            )

            with patch(
                "static_triage.scanner.inspect_tools",
                return_value=[capa_tool],
            ):
                with patch(
                    "static_triage.scanner.run_capa_batch",
                    return_value=capa_batch_result,
                ) as mocked_capa:
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

            mocked_capa.assert_called_once()

            call_args = mocked_capa.call_args
            selected_entries = call_args.args[0]
            scan_root = call_args.args[1]

            self.assertEqual(
                [
                    entry.relative_path
                    for entry in selected_entries
                ],
                ["program.exe"],
            )

            self.assertEqual(
                scan_root,
                sample.resolve(),
            )

            self.assertEqual(
                call_args.kwargs["executable"],
                "/usr/local/bin/capa",
            )

            report = json.loads(
                (
                    result.case_directory
                    / "report.json"
                ).read_text(encoding="utf-8")
            )

            capa_report = report["analyzers"]["capa"]

            self.assertEqual(
                capa_report["status"],
                "completed",
            )

            self.assertTrue(
                capa_report["complete"]
            )

            self.assertEqual(
                capa_report["capability_count"],
                1,
            )

            self.assertEqual(
                capa_report["results"][0]
                ["capabilities"][0]["name"],
                "send HTTP request",
            )

            raw_directory = (
                result.case_directory
                / "raw"
                / "capa"
            )

            raw_batch = json.loads(
                (
                    raw_directory
                    / "result.json"
                ).read_text(encoding="utf-8")
            )

            self.assertEqual(
                raw_batch["attempted_files"],
                1,
            )

            path_identifier = hashlib.sha256(
                os.fsencode("program.exe")
            ).hexdigest()[:16]

            file_directory = (
                raw_directory
                / f"0001-{path_identifier}"
            )

            self.assertTrue(
                (
                    file_directory
                    / "result.json"
                ).is_file()
            )

            self.assertTrue(
                (
                    file_directory
                    / "stdout.json"
                ).is_file()
            )

            self.assertTrue(
                (
                    file_directory
                    / "stderr.txt"
                ).is_file()
            )


if __name__ == "__main__":
    unittest.main()