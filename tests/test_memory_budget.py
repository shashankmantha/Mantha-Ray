from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from static_triage.capa import CapaResult, CapaStatus, run_capa_batch
from static_triage.case_summary import summarize
from static_triage.config import ScanLimits
from static_triage.deduplication import group_entries_by_sha256
from static_triage.memory_budget import (
    SCANNER_OVERHEAD_MIB,
    analysis_budget_mib,
    estimate_mib,
)
from static_triage.models import (
    EntryKind,
    EntryState,
    InventoryEntry,
    RoutingClass,
)
from static_triage.parallel import run_groups
from static_triage.reporting import _analysis_plan_lines
from static_triage.resource_profiles import resolve_profile
from static_triage.runner import run_command
from static_triage.scheduling import prioritize_groups

ROOT = Path(__file__).resolve().parents[1]
MIB = 1024**2


def entry(path, size):
    return InventoryEntry(
        relative_path=path,
        kind=EntryKind.REGULAR_FILE,
        state=EntryState.INVENTORIED,
        sha256=(path.encode().hex() * 64)[:64],
        size_bytes=size,
        routing_class=RoutingClass.PE_EXECUTABLE,
    )


def groups_of(**sizes):
    return prioritize_groups(
        group_entries_by_sha256([entry(n, s) for n, s in sizes.items()])
    )


class EstimateTests(unittest.TestCase):
    def test_tiers(self) -> None:
        self.assertEqual(estimate_mib("capa", 300_000), 768)
        self.assertEqual(estimate_mib("capa", 2_212_352), 1536)
        self.assertEqual(estimate_mib("capa", 8_557_056), 3584)
        self.assertEqual(estimate_mib("floss", 300_000), 2048)
        self.assertEqual(estimate_mib("floss", 2_500_000), 3072)
        self.assertEqual(estimate_mib("floss", 8_557_056), 4096)

    def test_unknown_size_is_treated_as_large(self) -> None:
        for size in (None, True, "big"):
            with self.subTest(size=size):
                self.assertEqual(estimate_mib("capa", size), 3584)

    def test_estimates_grow_with_size(self) -> None:
        sizes = [10, MIB, MIB + 1, 4 * MIB, 4 * MIB + 1, 50 * MIB]
        for analyzer in ("capa", "floss"):
            values = [estimate_mib(analyzer, size) for size in sizes]
            self.assertEqual(values, sorted(values))

    def test_budget_from_profile(self) -> None:
        self.assertEqual(analysis_budget_mib(4096), 4096 - SCANNER_OVERHEAD_MIB)
        self.assertEqual(resolve_profile("balanced").scan_limits(), ScanLimits())
        self.assertEqual(ScanLimits().analysis_memory_mib, 3840)
        custom = resolve_profile("balanced", {"memory_mib": 6144})
        self.assertEqual(custom.scan_limits().analysis_memory_mib, 5888)


class Tracker:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.active: set[str] = set()
        self.peak = 0
        self.company: dict[str, set[str]] = {}

    def run(self, name: str, seconds: float = 0.05) -> None:
        with self.lock:
            self.active.add(name)
            self.peak = max(self.peak, len(self.active))
            self.company.setdefault(name, set()).update(self.active - {name})
        time.sleep(seconds)
        with self.lock:
            for other in self.active - {name}:
                self.company.setdefault(name, set()).add(other)
            self.active.discard(name)


def run(groups, analyze, *, estimates, budget, workers=3, **extra):
    return run_groups(
        groups,
        analyze,
        label="capa",
        workers=workers,
        total_timeout_seconds=3600,
        timeout_for=lambda group: 300.0,
        outcome=lambda result: (True, False, 0.05),
        clock=time.monotonic,
        memory_budget_mib=budget,
        memory_for=lambda group: estimates[group.representative.relative_path],
        **extra,
    )


class DispatchTests(unittest.TestCase):
    def test_estimates_limit_how_many_run_together(self) -> None:
        tracker = Tracker()
        names = {f"f{i}.dll": 10 + i for i in range(6)}

        def analyze(group, timeout):
            tracker.run(group.representative.relative_path)

        run(
            groups_of(**names),
            analyze,
            estimates={name: 1000 for name in names},
            budget=2500,
        )
        self.assertEqual(tracker.peak, 2)

    def test_without_budget_worker_count_rules(self) -> None:
        tracker = Tracker()
        names = {f"f{i}.dll": 10 + i for i in range(6)}

        def analyze(group, timeout):
            tracker.run(group.representative.relative_path)

        run_groups(
            groups_of(**names),
            analyze,
            label="capa",
            workers=3,
            total_timeout_seconds=3600,
            timeout_for=lambda group: 300.0,
            outcome=lambda result: (True, False, 0.05),
            clock=time.monotonic,
        )
        self.assertEqual(tracker.peak, 3)

    def test_file_above_budget_runs_alone(self) -> None:
        tracker = Tracker()
        messages: list[str] = []

        def analyze(group, timeout):
            tracker.run(group.representative.relative_path)

        result = run(
            groups_of(**{"a.dll": 10, "b.dll": 20, "game.exe": 8 * MIB}),
            analyze,
            estimates={"a.dll": 500, "b.dll": 500, "game.exe": 4000},
            budget=3000,
            on_file=messages.append,
        )
        self.assertEqual(tracker.company["game.exe"], set())
        self.assertIn("capa 3/3 started alone: game.exe (8.0 MB)", messages)
        game = next(
            item for item in result.finished
            if item.group.representative.relative_path == "game.exe"
        )
        self.assertFalse(game.shared)
        self.assertEqual(game.memory_estimate_mib, 4000)

    def test_small_files_share_but_not_with_big_one(self) -> None:
        tracker = Tracker()

        def analyze(group, timeout):
            tracker.run(group.representative.relative_path)

        run(
            groups_of(**{"a.dll": 10, "b.dll": 20, "c.exe": 5 * MIB}),
            analyze,
            estimates={"a.dll": 700, "b.dll": 700, "c.exe": 2900},
            budget=3000,
        )
        self.assertIn("b.dll", tracker.company["a.dll"])
        self.assertEqual(tracker.company["c.exe"], set())


def capa_result(name, *, rc=0, peak=None):
    ok = rc == 0
    return CapaResult(
        status=CapaStatus.COMPLETED if ok else CapaStatus.ERROR,
        complete=ok,
        relative_path=name,
        return_code=rc,
        capabilities=(),
        timed_out=False,
        output_truncated=False,
        duration_seconds=1.0,
        stdout="{}" if ok else "",
        stderr="",
        error=None if ok else "killed",
        peak_memory_mib=peak,
    )


class BatchTests(unittest.TestCase):
    def run_batch(self, fake, entries, **options):
        with (
            patch("static_triage.capa.run_capa", side_effect=fake),
            tempfile.TemporaryDirectory() as temporary,
        ):
            return run_capa_batch(entries, Path(temporary), **options)

    def test_killed_alone_means_needs_more_memory(self) -> None:
        calls: list[str] = []

        def fake(target, scan_root, **_):
            name = target.relative_to(scan_root).as_posix()
            calls.append(name)
            if name == "DoorKickers2.exe":
                return capa_result(name, rc=-9, peak=3900.0)
            return capa_result(name, peak=600.0)

        batch = self.run_batch(
            fake,
            [entry("steam_api64.dll", 300_000), entry("DoorKickers2.exe", 8_557_056)],
            workers=2,
            memory_budget_mib=3840,
        )
        self.assertEqual(calls.count("DoorKickers2.exe"), 1)
        payload = batch.to_dict()
        dk = next(r for r in payload["results"] if r["relative_path"] == "DoorKickers2.exe")
        self.assertTrue(dk["needs_more_memory"])
        self.assertFalse(dk["retried_alone"])
        self.assertEqual(dk["peak_memory_mib"], 3900.0)
        self.assertEqual(dk["memory_estimate_mib"], 3584)
        self.assertIn("this profile needs more memory", batch.error)
        self.assertEqual(payload["memory_policy"]["budget_mib"], 3840)

        lines = _analysis_plan_lines(payload)
        self.assertIn(
            "- Memory planning: up to 3.8 GiB for analyses; "
            "files estimated to need more run alone",
            lines,
        )
        self.assertIn("- Highest memory used by one analysis: 3.8 GiB", lines)
        self.assertTrue(any("needs a profile with more memory" in l for l in lines))

    def test_no_budget_keeps_old_behaviour(self) -> None:
        batch = self.run_batch(
            lambda target, scan_root, **_: capa_result(
                target.relative_to(scan_root).as_posix()
            ),
            [entry("a.dll", 10)],
        )
        payload = batch.to_dict()
        self.assertIsNone(payload["memory_policy"])
        self.assertIsNone(payload["results"][0]["memory_estimate_mib"])
        self.assertFalse(payload["results"][0]["needs_more_memory"])


class RunnerPeakTests(unittest.TestCase):
    @unittest.skipUnless(Path("/proc/self/status").exists(), "needs /proc")
    def test_peak_memory_is_measured(self) -> None:
        result = run_command(
            [
                sys.executable,
                "-c",
                "import time; data = bytearray(80 * 1024 * 1024); "
                "data[::4096] = b'x' * len(data[::4096]); time.sleep(1.5)",
            ],
            timeout_seconds=30,
            max_output_bytes=1000,
        )
        self.assertEqual(result.return_code, 0)
        self.assertIsNotNone(result.peak_memory_mib)
        self.assertGreater(result.peak_memory_mib, 70)


class SummaryTests(unittest.TestCase):
    def test_peak_and_needs_more_memory_shown(self) -> None:
        report = {
            "status": "incomplete",
            "analyzers": {
                "capa": {
                    "results": [
                        {"relative_path": "DoorKickers2.exe", "complete": False,
                         "timed_out": False, "duration_seconds": 900,
                         "analysis_position": 1, "return_code": -9,
                         "needs_more_memory": True, "peak_memory_mib": 3900.0},
                        {"relative_path": "steam_api64.dll", "complete": True,
                         "timed_out": False, "duration_seconds": 26,
                         "analysis_position": 2, "peak_memory_mib": 612.0},
                    ],
                },
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            case = Path(temporary) / "case-20261022T000000Z-aaaaaaaa"
            case.mkdir()
            (case / "report.json").write_text(json.dumps(report))
            text = summarize(case)
        self.assertIn("1 need more memory", text)
        self.assertIn("3.8 GiB", text)
        self.assertIn("0.6 GiB", text)
        self.assertIn("needs more memory than this profile", text)


class ContainerfileTests(unittest.TestCase):
    def test_inherited_health_check_disabled(self) -> None:
        self.assertIn("HEALTHCHECK NONE", (ROOT / "Containerfile").read_text())


if __name__ == "__main__":
    unittest.main()