from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from static_triage.config import ScanConfig
from static_triage.models import SCHEMA_VERSION
from static_triage.resource_profiles import resolve_profile
from static_triage.scan_record import (
    StageTimer,
    compare_limits,
    read_container_limits,
    resources_record,
)
from static_triage.scanner import run_inventory_scan

MIB = 1024**2


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class StageTimerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.timer = StageTimer(clock=self.clock, wall_clock=self.clock)

    def test_running_then_completed_records_duration(self) -> None:
        self.timer.observe("capa", "running")
        self.clock.now += 3600.25
        self.timer.observe("capa", "incomplete")
        record = self.timer.to_dict()["capa"]
        self.assertEqual(record["status"], "incomplete")
        self.assertEqual(record["duration_seconds"], 3600.25)
        self.assertIsNotNone(record["started_at"])
        self.assertIsNotNone(record["completed_at"])

    def test_repeated_running_keeps_first_start(self) -> None:
        self.timer.observe("capa", "running")
        started = self.timer.to_dict()["capa"]["started_at"]
        self.clock.now += 100
        self.timer.observe("capa", "running")
        self.clock.now += 50
        self.timer.observe("capa", "incomplete")
        record = self.timer.to_dict()["capa"]
        self.assertEqual(record["duration_seconds"], 150)
        self.assertEqual(record["started_at"], started)

    def test_unavailable_without_running_has_no_duration(self) -> None:
        self.timer.observe("floss", "unavailable")
        record = self.timer.to_dict()["floss"]
        self.assertEqual(record["status"], "unavailable")
        self.assertIsNone(record["started_at"])
        self.assertIsNone(record["duration_seconds"])

    def test_unfinished_stage_stays_running(self) -> None:
        self.timer.observe("report", "running")
        record = self.timer.to_dict()["report"]
        self.assertEqual(record["status"], "running")
        self.assertIsNone(record["duration_seconds"])

    def test_non_terminal_statuses_ignored(self) -> None:
        self.timer.observe("capa", "waiting")
        self.assertEqual(self.timer.to_dict(), {})

    def test_wrap_forwards_every_event(self) -> None:
        seen = []
        wrapped = self.timer.wrap(lambda *event: seen.append(event))
        wrapped("clamav", "running", "scanning")
        wrapped("clamav", "completed", "done")
        self.assertEqual(
            seen,
            [("clamav", "running", "scanning"), ("clamav", "completed", "done")],
        )
        self.assertEqual(self.timer.to_dict()["clamav"]["status"], "completed")

    def test_wrap_without_callback(self) -> None:
        self.timer.wrap(None)("inventory", "running", "x")
        self.assertIn("inventory", self.timer.to_dict())

    def test_to_dict_is_a_copy(self) -> None:
        self.timer.observe("capa", "running")
        self.timer.to_dict()["capa"]["status"] = "tampered"
        self.assertEqual(self.timer.to_dict()["capa"]["status"], "running")


class ContainerLimitTests(unittest.TestCase):
    def _cgroup(self, files: dict[str, str]) -> Path:
        root = Path(tempfile.mkdtemp())
        for name, text in files.items():
            (root / name).write_text(text)
        return root

    def test_reads_cgroup_v2_limits(self) -> None:
        root = self._cgroup(
            {
                "memory.max": f"{4096 * MIB}\n",
                "cpu.max": "200000 100000\n",
                "pids.max": "256\n",
            }
        )
        observed = read_container_limits(root, root)
        self.assertEqual(observed["source"], "cgroup-v2")
        self.assertEqual(observed["memory_bytes"], 4096 * MIB)
        self.assertEqual(observed["cpus"], 2.0)
        self.assertEqual(observed["pids"], 256)
        self.assertIsInstance(observed["tmp_bytes"], int)

    def test_fractional_cpus(self) -> None:
        root = self._cgroup({"cpu.max": "150000 100000"})
        self.assertEqual(read_container_limits(root, root)["cpus"], 1.5)

    def test_unlimited_values_are_none(self) -> None:
        root = self._cgroup(
            {"memory.max": "max", "cpu.max": "max 100000", "pids.max": "max"}
        )
        observed = read_container_limits(root, root)
        self.assertIsNone(observed["memory_bytes"])
        self.assertIsNone(observed["cpus"])
        self.assertIsNone(observed["pids"])

    def test_garbage_is_ignored(self) -> None:
        root = self._cgroup(
            {"memory.max": "lots", "cpu.max": "1 2 3", "pids.max": "-5"}
        )
        observed = read_container_limits(root, root)
        self.assertIsNone(observed["memory_bytes"])
        self.assertIsNone(observed["cpus"])
        self.assertIsNone(observed["pids"])

    def test_missing_cgroup_reported_unavailable(self) -> None:
        missing = Path(tempfile.mkdtemp()) / "nope"
        observed = read_container_limits(missing, missing)
        self.assertEqual(observed["source"], "unavailable")
        self.assertIsNone(observed["tmp_bytes"])


class ResourcesRecordTests(unittest.TestCase):
    def _profile_record(self, profile):
        return {**profile.to_dict(), "changed": profile.changed_fields()}

    def test_matching_limits_are_enforced(self) -> None:
        profile = resolve_profile("balanced")
        observed = {
            "source": "cgroup-v2",
            "memory_bytes": 4096 * MIB,
            "cpus": 2.0,
            "pids": 256,
            "tmp_bytes": 512 * MIB,
        }
        record = resources_record(self._profile_record(profile), observed)
        self.assertTrue(record["enforced"])
        self.assertEqual(record["not_enforced"], [])
        self.assertEqual(record["profile"], "balanced")
        self.assertEqual(record["changed"], {})

    def test_mismatches_are_listed(self) -> None:
        values = resolve_profile("high").values()
        observed = {
            "memory_bytes": 4096 * MIB,
            "cpus": 4.0,
            "pids": None,
            "tmp_bytes": 1024 * MIB + 4096,
        }
        self.assertEqual(
            compare_limits(values, observed),
            ["memory_bytes", "pids"],
        )

    def test_custom_record_keeps_changes(self) -> None:
        profile = resolve_profile("balanced", {"cpus": 1.5})
        record = resources_record(
            self._profile_record(profile),
            {"source": "unavailable"},
        )
        self.assertEqual(record["profile"], "custom")
        self.assertEqual(record["base"], "balanced")
        self.assertEqual(record["changed"], {"cpus": 1.5})
        self.assertFalse(record["enforced"])


class ReportIntegrationTests(unittest.TestCase):
    @patch("static_triage.scanner.inspect_tools", return_value=[])
    def test_scan_records_timings_and_resources(self, _tools) -> None:
        profile = resolve_profile("constrained")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            sample = base / "staging" / "sample"
            sample.mkdir(parents=True)
            (sample / "readme.txt").write_text("benign\n")
            events = []
            result = run_inventory_scan(
                "sample",
                ScanConfig(
                    staging_root=base / "staging",
                    results_root=base / "results",
                    limits=profile.scan_limits(),
                    resource_profile={
                        **profile.to_dict(),
                        "changed": profile.changed_fields(),
                    },
                ),
                on_progress=lambda *event: events.append(event),
            )
            report = json.loads(
                (result.case_directory / "report.json").read_text()
            )
            manifest = json.loads(
                (result.case_directory / "manifest.json").read_text()
            )
            markdown = result.report_path.read_text()

        self.assertEqual(report["schema_version"], SCHEMA_VERSION)
        self.assertTrue(SCHEMA_VERSION.startswith("0.2."))

        timings = report["stage_timings"]
        self.assertEqual(timings["inventory"]["status"], "completed")
        self.assertIsInstance(timings["inventory"]["duration_seconds"], float)
        for stage in ("clamav", "capa", "floss"):
            self.assertEqual(timings[stage]["status"], "unavailable")
        self.assertEqual(timings["report"]["status"], "running")

        self.assertEqual(report["resources"]["profile"], "constrained")
        self.assertEqual(report["resources"]["values"]["cpus"], 1)
        self.assertIn("observed", report["resources"])
        self.assertEqual(manifest["resources"], report["resources"])

        # Progress events still reach the caller unchanged.
        self.assertIn(("inventory", "completed"), [e[:2] for e in events])

        self.assertIn("## Resources", markdown)
        self.assertIn("**Constrained**", markdown)
        self.assertIn("## Stage timings", markdown)
        self.assertIn("| inventory | completed |", markdown)
        self.assertNotIn("| report |", markdown)
        self.assertIn("capa budget: 30 min", markdown)

    @patch("static_triage.scanner.inspect_tools", return_value=[])
    def test_scan_without_profile_still_works(self, _tools) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            sample = base / "staging" / "sample"
            sample.mkdir(parents=True)
            (sample / "a.txt").write_text("x")
            result = run_inventory_scan(
                "sample",
                ScanConfig(
                    staging_root=base / "staging",
                    results_root=base / "results",
                ),
            )
            report = json.loads(
                (result.case_directory / "report.json").read_text()
            )
        self.assertIsNone(report["resources"])
        self.assertIn("inventory", report["stage_timings"])


if __name__ == "__main__":
    unittest.main()