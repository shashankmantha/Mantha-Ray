from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from static_triage.host_scan import (
    DockerScanRequest,
    HostScanError,
    build_docker_command,
    parse_scan_output,
    validate_request,
)


class HostScanTests(unittest.TestCase):
    def test_valid_request_builds_hardened_read_only_mount(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            results = base / "results"
            source.mkdir()
            results.mkdir()

            request = validate_request(
                DockerScanRequest(source, results)
            )

            with patch("static_triage.host_scan.os.getuid", return_value=10), \
                    patch(
                        "static_triage.host_scan.os.getgid",
                        return_value=20,
                    ):
                command = build_docker_command(
                    request,
                    "/usr/bin/docker",
                    "test-container",
                )

            self.assertIn("none", command)
            self.assertIn("ALL", command)
            self.assertIn("no-new-privileges:true", command)
            self.assertIn("label=disable", command)
            self.assertIn("10:20", command)
            self.assertIn(
                "type=bind,source="
                f"{source},target=/staging/input,readonly",
                command,
            )
            self.assertEqual(command[-6:], [
                "scan",
                "input",
                "--staging-root",
                "/staging",
                "--results-root",
                "/results",
            ])

    def test_overlapping_directories_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            results = source / "results"
            results.mkdir()

            with self.assertRaisesRegex(HostScanError, "overlap"):
                validate_request(DockerScanRequest(source, results))

    def test_comma_in_mount_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source,files"
            results = base / "results"
            source.mkdir()
            results.mkdir()

            with self.assertRaisesRegex(HostScanError, "commas"):
                validate_request(DockerScanRequest(source, results))

    def test_output_paths_are_derived_from_validated_case_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            results = Path(temporary)
            case_id = "case-20260915T120000Z-1234abcd"
            case_directory = results / case_id
            case_directory.mkdir()
            report = case_directory / "report.md"
            report.write_text("# Report\n", encoding="utf-8")
            output = json.dumps(
                {
                    "ok": True,
                    "case_id": case_id,
                    "status": "needs_review",
                    "report_path": "/untrusted/elsewhere/report.md",
                }
            )

            parsed = parse_scan_output(output, "", results)

            self.assertEqual(parsed.report_path, report)
            self.assertEqual(parsed.status, "needs_review")

    def test_invalid_case_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = json.dumps(
                {
                    "ok": True,
                    "case_id": "../../escape",
                    "status": "needs_review",
                }
            )

            with self.assertRaisesRegex(HostScanError, "case ID"):
                parse_scan_output(output, "", Path(temporary))

    def test_scanner_error_is_preserved(self) -> None:
        output = json.dumps(
            {
                "ok": False,
                "error": "selected input was rejected",
            }
        )

        with self.assertRaisesRegex(
            HostScanError,
            "selected input was rejected",
        ):
            parse_scan_output(output, "", Path("/unused"))


if __name__ == "__main__":
    unittest.main()
