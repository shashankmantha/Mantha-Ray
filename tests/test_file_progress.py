from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from static_triage.capa import CapaResult, CapaStatus, run_capa_batch
from static_triage.case_summary import find_case, summarize
from static_triage.config import ScanConfig
from static_triage.deduplication import group_entries_by_sha256
from static_triage.file_progress import (
    MAX_PATH_CHARS,
    finished_message,
    format_size,
    short_path,
    started_message,
)
from static_triage.floss import FlossResult, FlossStatus, run_floss_batch
from static_triage.models import (
    EntryKind,
    EntryState,
    InventoryEntry,
    RoutingClass,
    ToolInfo,
)
from static_triage.scanner import run_inventory_scan

ROOT = Path(__file__).resolve().parents[1]


def entry(path, size, digest=None):
    return InventoryEntry(
        relative_path=path,
        kind=EntryKind.REGULAR_FILE,
        state=EntryState.INVENTORIED,
        sha256=digest or (path.encode().hex() * 64)[:64],
        size_bytes=size,
        routing_class=RoutingClass.PE_EXECUTABLE,
    )


def one_group(*entries):
    (group,) = group_entries_by_sha256(list(entries))
    return group


class MessageTests(unittest.TestCase):
    def test_started_message(self) -> None:
        group = one_group(entry("steam_api64.dll", 300_000))
        self.assertEqual(
            started_message("capa", 5, 47, group),
            "capa 5/47 started: steam_api64.dll (293 KB)",
        )

    def test_finished_outcomes(self) -> None:
        group = one_group(entry("a.dll", 10))
        cases = {
            (True, False, 31): "capa 1/2 completed in 31 s: a.dll",
            (False, True, 300): "capa 1/2 timed out after 5 min: a.dll",
            (False, False, 4): "capa 1/2 failed after 4 s: a.dll",
        }
        for (complete, timed_out, seconds), expected in cases.items():
            with self.subTest(expected=expected):
                self.assertEqual(
                    finished_message(
                        "capa", 1, 2, group,
                        complete=complete,
                        timed_out=timed_out,
                        duration_seconds=seconds,
                    ),
                    expected,
                )

    def test_duplicates_mentioned(self) -> None:
        same = "a" * 64
        group = one_group(
            entry("v1/steam_api.dll", 100, same),
            entry("v2/steam_api.dll", 100, same),
            entry("v3/steam_api.dll", 100, same),
        )
        self.assertIn("(+2 identical copies)", started_message("capa", 1, 1, group))

    def test_untrusted_paths_are_bounded_and_single_line(self) -> None:
        nasty = "dir/" + "x" * 300 + "\x1b[31m\nfake.dll"
        shown = short_path(nasty)
        self.assertLessEqual(len(shown), MAX_PATH_CHARS)
        self.assertNotIn("\x1b", shown)
        self.assertNotIn("\n", shown)
        self.assertTrue(shown.endswith("fake.dll"))

    def test_sizes(self) -> None:
        self.assertEqual(format_size(512), "512 B")
        self.assertEqual(format_size(51_487_232), "49.1 MB")
        self.assertEqual(format_size(None), "size unknown")
        self.assertEqual(format_size(True), "size unknown")


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now


class BatchCallbackTests(unittest.TestCase):
    ENTRIES = [entry("big.dll", 5_000_000), entry("small.dll", 1_000)]

    def _capa(self, clock):
        def run(target, scan_root, *, timeout_seconds, **_):
            relative = target.relative_to(scan_root).as_posix()
            slow = relative == "big.dll"
            spent = timeout_seconds if slow else 20.0
            clock.now += spent
            return CapaResult(
                status=CapaStatus.TIMED_OUT if slow else CapaStatus.COMPLETED,
                complete=not slow,
                relative_path=relative,
                return_code=0,
                capabilities=(),
                timed_out=slow,
                output_truncated=False,
                duration_seconds=spent,
                stdout="",
                stderr="",
            )
        return run

    def test_capa_reports_each_file_in_order(self) -> None:
        clock = FakeClock()
        messages: list[str] = []
        with (
            patch("static_triage.capa.run_capa", side_effect=self._capa(clock)),
            patch("static_triage.capa.time", SimpleNamespace(monotonic=clock.monotonic)),
            tempfile.TemporaryDirectory() as temporary,
        ):
            run_capa_batch(
                self.ENTRIES,
                Path(temporary),
                file_timeout_seconds=300,
                on_file=messages.append,
            )
        self.assertEqual(
            messages,
            [
                "capa 1/2 started: small.dll (1000 B)",
                "capa 1/2 completed in 20 s: small.dll",
                "capa 2/2 started: big.dll (4.8 MB)",
                "capa 2/2 timed out after 5 min: big.dll",
            ],
        )

    def test_floss_reports_each_file(self) -> None:
        def run(target, scan_root, **_):
            return FlossResult(
                status=FlossStatus.COMPLETED,
                complete=True,
                relative_path=target.relative_to(scan_root).as_posix(),
                return_code=0,
                strings=(),
                total_strings=0,
                strings_truncated=False,
                timed_out=False,
                output_truncated=False,
                duration_seconds=2.0,
                stdout="{}",
                stderr="",
            )

        messages: list[str] = []
        with (
            patch("static_triage.floss.run_floss", side_effect=run),
            tempfile.TemporaryDirectory() as temporary,
        ):
            run_floss_batch(self.ENTRIES, Path(temporary), on_file=messages.append)
        self.assertEqual(messages[0], "FLOSS 1/2 started: small.dll (1000 B)")
        self.assertEqual(messages[-1], "FLOSS 2/2 completed in 2 s: big.dll")

    def test_callback_optional(self) -> None:
        clock = FakeClock()
        with (
            patch("static_triage.capa.run_capa", side_effect=self._capa(clock)),
            patch("static_triage.capa.time", SimpleNamespace(monotonic=clock.monotonic)),
            tempfile.TemporaryDirectory() as temporary,
        ):
            result = run_capa_batch(self.ENTRIES, Path(temporary))
        self.assertEqual(result.attempted_files, 2)


class ScannerIntegrationTests(unittest.TestCase):
    def test_progress_events_and_stage_timing(self) -> None:
        tools = [ToolInfo(name="capa", executable="/usr/bin/capa", available=True)]

        def run(target, scan_root, **_):
            return CapaResult(
                status=CapaStatus.COMPLETED,
                complete=True,
                relative_path=target.relative_to(scan_root).as_posix(),
                return_code=0,
                capabilities=(),
                timed_out=False,
                output_truncated=False,
                duration_seconds=1.0,
                stdout="{}",
                stderr="",
            )

        pe = bytearray(256)
        pe[0:2] = b"MZ"
        pe[0x3C:0x40] = (128).to_bytes(4, "little")
        pe[128:132] = b"PE\x00\x00"
        pe[150:152] = (0x2000).to_bytes(2, "little")
        events = []
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            sample = base / "staging" / "sample"
            sample.mkdir(parents=True)
            (sample / "a.dll").write_bytes(bytes(pe))
            with (
                patch("static_triage.scanner.inspect_tools", return_value=tools),
                patch("static_triage.capa.run_capa", side_effect=run),
            ):
                result = run_inventory_scan(
                    "sample",
                    ScanConfig(
                        staging_root=base / "staging",
                        results_root=base / "results",
                    ),
                    on_progress=lambda *event: events.append(event),
                )
            report = json.loads((result.case_directory / "report.json").read_text())

        capa_messages = [message for stage, _, message in events if stage == "capa"]
        self.assertIn("capa 1/1 started: a.dll (256 B)", capa_messages)
        self.assertTrue(any(m.startswith("capa 1/1 completed") for m in capa_messages))
        timing = report["stage_timings"]["capa"]
        self.assertEqual(timing["status"], "completed")
        self.assertIsNotNone(timing["started_at"])


class SummaryTests(unittest.TestCase):
    def _case(self, root: Path, name: str, report: dict) -> Path:
        case = root / name
        case.mkdir()
        (case / "report.json").write_text(json.dumps(report))
        return case

    REPORT = {
        "status": "incomplete",
        "summary": {"regular_files": 3485, "total_bytes": 3_095_034_730},
        "resources": {
            "profile": "balanced",
            "base": "balanced",
            "values": {"cpus": 2, "memory_mib": 4096},
            "enforced": True,
        },
        "stage_timings": {
            "inventory": {"duration_seconds": 28},
            "capa": {"duration_seconds": 3600},
        },
        "analyzers": {
            "clamav": {"status": "clean", "findings": []},
            "capa": {
                "unique_eligible_files": 47,
                "skipped_due_to_timeout": 29,
                "results": [
                    {"relative_path": "big.dll", "complete": False,
                     "timed_out": True, "duration_seconds": 300,
                     "analysis_position": 2},
                    {"relative_path": "steam_api64.dll", "complete": True,
                     "timed_out": False, "duration_seconds": 31,
                     "analysis_position": 1},
                ],
            },
            "floss": {
                "unique_eligible_files": 30,
                "skipped_due_to_size": 3,
                "results": [],
            },
        },
        "incomplete_reasons": ["capa analysis was incomplete"],
    }

    def test_summary_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = self._case(Path(temporary), "case-20261018T204134Z-81a4f265", self.REPORT)
            text = summarize(case)
        self.assertIn("(Incomplete)", text)
        self.assertIn("Balanced · 2 CPUs · 4 GiB · limits confirmed", text)
        self.assertIn("inventory 28 s", text)
        self.assertIn("29 not reached", text)
        self.assertIn("3 over size limit (n/a)", text)
        order = text.index("steam_api64.dll") < text.index("big.dll")
        self.assertTrue(order)

    def test_newest_case_is_chosen(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._case(root, "case-20261003T000000Z-aaaaaaaa", self.REPORT)
            newest = self._case(root, "case-20261018T000000Z-bbbbbbbb", self.REPORT)
            (root / "case-not-valid").mkdir()
            self.assertEqual(find_case(root), newest)

    def test_terminal_escapes_are_stripped(self) -> None:
        report = json.loads(json.dumps(self.REPORT))
        report["analyzers"]["capa"]["results"][0]["relative_path"] = "\x1b]0;pwned\x07evil.dll"
        with tempfile.TemporaryDirectory() as temporary:
            case = self._case(Path(temporary), "case-20261018T204134Z-81a4f265", report)
            text = summarize(case)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x07", text)
        self.assertIn("evil.dll", text)

    def test_older_case_without_new_fields(self) -> None:
        old = {"status": "incomplete", "analyzers": {"capa": {"results": [
            {"relative_path": "a.dll", "complete": True, "duration_seconds": 5}
        ]}}}
        with tempfile.TemporaryDirectory() as temporary:
            case = self._case(Path(temporary), "case-20260925T000000Z-cccccccc", old)
            text = summarize(case)
        self.assertIn("not recorded (older case)", text)
        self.assertIn("order not recorded", text)

    def test_missing_folder(self) -> None:
        with self.assertRaises(SystemExit):
            find_case(Path("/nonexistent/mantha"))

    def test_script_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = self._case(Path(temporary), "case-20261018T204134Z-81a4f265", self.REPORT)
            completed = subprocess.run(
                [str(ROOT / "scripts" / "summary.sh"), str(case)],
                capture_output=True,
                text=True,
                timeout=60,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Case     case-20261018T204134Z-81a4f265", completed.stdout)


if __name__ == "__main__":
    unittest.main()