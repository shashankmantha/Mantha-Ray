from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from threading import Event

from static_triage.host_scan import (
    DockerScanRequest,
    DockerScanResult,
    HostScanError,
)
from static_triage.web_service import ScanService


class SuccessfulController:
    image = "static-triage:core"

    def preflight(self) -> str:
        return "test-version"

    def scan(
        self,
        request: DockerScanRequest,
        on_status=None,
    ) -> DockerScanResult:
        if on_status is not None:
            on_status("Analyzer fixture is running.")

        case_id = (
            "case-20260920T120000Z-1234abcd"
        )

        case_directory = (
            request.results_directory / case_id
        )

        case_directory.mkdir()

        report_json = {
            "case_id": case_id,
            "status": "needs_review",
            "summary": {
                "regular_files": 1,
                "hashed_files": 1,
            },
        }

        (
            case_directory / "report.json"
        ).write_text(
            json.dumps(report_json),
            encoding="utf-8",
        )

        report_path = (
            case_directory / "report.md"
        )

        report_path.write_text(
            "# Test report\n",
            encoding="utf-8",
        )

        return DockerScanResult(
            case_id=case_id,
            status="needs_review",
            case_directory=case_directory,
            report_path=report_path,
            output="",
        )

    def cancel(self) -> None:
        return None


class BlockingController:
    image = "static-triage:core"

    def __init__(self) -> None:
        self.release = Event()

    def preflight(self) -> str:
        self.release.wait(timeout=2)

        return "test-version"

    def scan(
        self,
        request,
        on_status=None,
    ):
        raise HostScanError(
            "Test scan should not reach analysis."
        )

    def cancel(self) -> None:
        self.release.set()


def wait_for_terminal_state(
    service: ScanService,
    scan_id: str,
) -> dict[str, object]:
    deadline = time.monotonic() + 3

    while time.monotonic() < deadline:
        state = service.get(scan_id)

        if state["state"] in {
            "completed",
            "failed",
            "cancelled",
        }:
            return state

        time.sleep(0.01)

    raise AssertionError(
        "Scan service did not reach a terminal state."
    )


class WebScanServiceTests(unittest.TestCase):
    def test_completed_scan_includes_reports(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            results = base / "results"

            source.mkdir()

            service = ScanService(
                SuccessfulController()
            )

            started = service.start(
                str(source),
                str(results),
            )

            finished = wait_for_terminal_state(
                service,
                str(started["scan_id"]),
            )

            self.assertEqual(
                finished["state"],
                "completed",
            )

            result = finished["result"]

            self.assertIsInstance(
                result,
                dict,
            )

            assert isinstance(result, dict)

            self.assertEqual(
                result["status"],
                "needs_review",
            )

            self.assertEqual(
                result["report_markdown"],
                "# Test report\n",
            )

            report = result["report"]

            self.assertIsInstance(
                report,
                dict,
            )

            assert isinstance(report, dict)

            summary = report["summary"]

            self.assertIsInstance(
                summary,
                dict,
            )

            assert isinstance(summary, dict)

            self.assertEqual(
                summary["hashed_files"],
                1,
            )

    def test_overlapping_results_are_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = (
                Path(temporary) / "source"
            )

            source.mkdir()

            nested_results = (
                source / "new-results"
            )

            service = ScanService(
                SuccessfulController()
            )

            with self.assertRaisesRegex(
                HostScanError,
                "overlap",
            ):
                service.start(
                    str(source),
                    str(nested_results),
                )

            self.assertFalse(
                nested_results.exists()
            )

    def test_only_one_scan_may_be_active(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            first_source = base / "first"
            second_source = base / "second"
            results = base / "results"

            first_source.mkdir()
            second_source.mkdir()

            controller = BlockingController()
            service = ScanService(controller)

            started = service.start(
                str(first_source),
                str(results),
            )

            with self.assertRaisesRegex(
                HostScanError,
                "already running",
            ):
                service.start(
                    str(second_source),
                    str(results),
                )

            service.cancel(
                str(started["scan_id"])
            )

            finished = wait_for_terminal_state(
                service,
                str(started["scan_id"]),
            )

            self.assertEqual(
                finished["state"],
                "cancelled",
            )


if __name__ == "__main__":
    unittest.main()