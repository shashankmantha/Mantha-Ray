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
        on_progress=None,
    ) -> DockerScanResult:
        if on_status is not None:
            on_status("Analyzer fixture is running.")

        if on_progress is not None:
            for stage in (
                "inventory",
                "clamav",
                "capa",
                "floss",
                "report",
            ):
                on_progress(
                    stage,
                    "running",
                    f"{stage} is running.",
                )
                on_progress(
                    stage,
                    "completed",
                    f"{stage} completed.",
                )

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
                "errors": 0,
                "limit_exceeded": 0,
            },
            "analyzers": {
                "clamav": {
                    "status": "clean",
                    "complete": True,
                },
                "capa": {
                    "status": "completed",
                    "complete": True,
                },
                "floss": {
                    "status": "completed",
                    "complete": True,
                },
            },
        }

        (
            case_directory / "report.json"
        ).write_text(
            json.dumps(report_json),
            encoding="utf-8",
        )

        (
            case_directory / "files.jsonl"
        ).write_text(
            json.dumps(
                {
                    "detected_type": "ELF 64-bit",
                    "error": None,
                    "evidence": [],
                    "kind": "regular_file",
                    "mode": "0o755",
                    "relative_path": "elf-test/true",
                    "routing_class": "elf",
                    "sha256": (
                        "7ab6c80be265496fa860ac26f3c15fb8"
                        "210f7b01da72fb9452ba5c0ef8f050d7"
                    ),
                    "size_bytes": 32304,
                    "state": "inventoried",
                }
            )
            + "\n",
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
        on_progress=None,
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

            artifacts = result["artifacts"]

            self.assertIsInstance(
                artifacts,
                list,
            )
            assert isinstance(artifacts, list)

            self.assertEqual(
                artifacts,
                [
                    {
                        "relative_path": "elf-test/true",
                        "kind": "regular_file",
                        "detected_type": "ELF 64-bit",
                        "routing_class": "elf",
                        "state": "inventoried",
                        "mode": "0o755",
                        "size_bytes": 32304,
                        "sha256": (
                            "7ab6c80be265496fa860ac26f3c15fb8"
                            "210f7b01da72fb9452ba5c0ef8f050d7"
                        ),
                        "review_flags": 0,
                        "error": None,
                    }
                ],
            )

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

            self.assertEqual(
                finished["stages"],
                {
                    "inventory": "completed",
                    "clamav": "completed",
                    "capa": "completed",
                    "floss": "completed",
                    "report": "completed",
                },
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

    def test_completed_scan_is_available_to_new_service(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source-folder"
            results = base / "results"
            source.mkdir()

            first_service = ScanService(
                SuccessfulController()
            )
            started = first_service.start(
                str(source),
                str(results),
            )
            finished = wait_for_terminal_state(
                first_service,
                str(started["scan_id"]),
            )
            result = finished["result"]

            self.assertIsInstance(result, dict)
            assert isinstance(result, dict)

            case_directory = Path(
                str(result["case_directory"])
            )

            self.assertTrue(
                (
                    case_directory
                    / "web-session.json"
                ).is_file()
            )

            restarted_service = ScanService(
                SuccessfulController()
            )
            history = restarted_service.list_cases(
                str(results)
            )
            cases = history["cases"]

            self.assertIsInstance(cases, list)
            assert isinstance(cases, list)
            self.assertEqual(len(cases), 1)
            self.assertEqual(
                cases[0]["label"],
                "source-folder",
            )
            self.assertEqual(
                cases[0]["status"],
                "needs_review",
            )

            loaded = restarted_service.load_case(
                str(results),
                str(result["case_id"]),
            )

            self.assertEqual(
                loaded["state"],
                "completed",
            )
            self.assertEqual(
                loaded["source_directory"],
                str(source.resolve()),
            )

            loaded_result = loaded["result"]
            self.assertIsInstance(
                loaded_result,
                dict,
            )
            assert isinstance(loaded_result, dict)
            self.assertEqual(
                loaded_result["report_markdown"],
                "# Test report\n",
            )

    def test_history_supports_cases_without_session_metadata(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            results = Path(temporary)
            case_id = (
                "case-20260920T120000Z-1234abcd"
            )
            case_directory = results / case_id
            case_directory.mkdir()
            (case_directory / "report.json").write_text(
                json.dumps(
                    {
                        "case_id": case_id,
                        "status": "needs_review",
                    }
                ),
                encoding="utf-8",
            )
            (case_directory / "report.md").write_text(
                "# Existing report\n",
                encoding="utf-8",
            )

            service = ScanService(
                SuccessfulController()
            )
            history = service.list_cases(
                str(results)
            )
            cases = history["cases"]

            self.assertIsInstance(cases, list)
            assert isinstance(cases, list)
            self.assertEqual(len(cases), 1)
            self.assertEqual(
                cases[0]["label"],
                case_id,
            )

            loaded = service.load_case(
                str(results),
                case_id,
            )
            self.assertEqual(
                loaded["state"],
                "completed",
            )

    def test_history_ignores_incomplete_and_symlinked_cases(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            results = base / "results"
            outside = base / "outside"
            results.mkdir()
            outside.mkdir()

            incomplete = (
                results
                / "case-20260920T120000Z-1234abcd"
            )
            incomplete.mkdir()

            linked = (
                results
                / "case-20260920T130000Z-abcdef12"
            )
            linked.symlink_to(
                outside,
                target_is_directory=True,
            )

            service = ScanService(
                SuccessfulController()
            )
            history = service.list_cases(
                str(results)
            )

            self.assertEqual(
                history["cases"],
                [],
            )

            with self.assertRaisesRegex(
                HostScanError,
                "Symbolic-link",
            ):
                service.load_case(
                    str(results),
                    linked.name,
                )

    def test_history_rejects_invalid_case_id(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            service = ScanService(
                SuccessfulController()
            )

            with self.assertRaisesRegex(
                HostScanError,
                "case ID",
            ):
                service.load_case(
                    temporary,
                    "../../escape",
                )

    def test_missing_history_directory_is_empty(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            service = ScanService(
                SuccessfulController()
            )
            missing = Path(temporary) / "missing"

            self.assertEqual(
                service.list_cases(str(missing)),
                {
                    "cases": [],
                    "truncated": False,
                },
            )


if __name__ == "__main__":
    unittest.main()
