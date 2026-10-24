from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from static_triage.capa import CapaResult, CapaStatus, run_capa_batch
from static_triage.case_summary import summarize
from static_triage.config import ScanConfig, ScanLimits
from static_triage.deduplication import group_entries_by_sha256
from static_triage.floss import FlossResult, FlossStatus, run_floss_batch
from static_triage.models import (
    SCHEMA_VERSION,
    EntryKind,
    EntryState,
    InventoryEntry,
    RoutingClass,
    ToolInfo,
)
from static_triage.parallel import (
    TIMEOUT_REFERENCE_BYTES,
    run_groups,
    scaled_timeout,
)
from static_triage.resource_profiles import (
    PRESETS,
    ResourceProfileError,
    resolve_profile,
)
from static_triage.scheduling import prioritize_groups

MIB = TIMEOUT_REFERENCE_BYTES


def entry(path, size):
    return InventoryEntry(
        relative_path=path,
        kind=EntryKind.REGULAR_FILE,
        state=EntryState.INVENTORIED,
        sha256=(path.encode().hex() * 64)[:64],
        size_bytes=size,
        routing_class=RoutingClass.PE_EXECUTABLE,
    )


def groups_of(*sizes):
    entries = [entry(f"f{i}.dll", size) for i, size in enumerate(sizes)]
    return prioritize_groups(group_entries_by_sha256(entries))


def capa_result(relative, *, complete=True, timed_out=False, seconds=1.0):
    return CapaResult(
        status=CapaStatus.COMPLETED if complete else CapaStatus.TIMED_OUT,
        complete=complete,
        relative_path=relative,
        return_code=0,
        capabilities=(),
        timed_out=timed_out,
        output_truncated=False,
        duration_seconds=seconds,
        stdout="{}",
        stderr="",
    )


class ScaledTimeoutTests(unittest.TestCase):
    def test_small_and_unknown_files_get_base(self) -> None:
        for size in (0, 300_000, MIB, None, True, "big"):
            with self.subTest(size=size):
                self.assertEqual(
                    scaled_timeout(size, base_seconds=300, max_seconds=1800),
                    300,
                )

    def test_grows_with_size_up_to_cap(self) -> None:
        # OpenAL32.dll and DoorKickers2.exe from the Door Kickers 2 run.
        self.assertAlmostEqual(
            scaled_timeout(2_212_352, base_seconds=300, max_seconds=1800),
            300 * 2_212_352 / MIB,
        )
        self.assertEqual(
            scaled_timeout(8_557_056, base_seconds=300, max_seconds=1800),
            1800,
        )

    def test_cap_equal_to_base_disables_scaling(self) -> None:
        self.assertEqual(
            scaled_timeout(50 * MIB, base_seconds=300, max_seconds=300),
            300,
        )


class RunGroupsTests(unittest.TestCase):
    def run_simple(self, groups, analyze, **overrides):
        options = dict(
            label="capa",
            workers=2,
            total_timeout_seconds=3600,
            timeout_for=lambda group: 300.0,
            outcome=lambda result: (True, False, 1.0),
            clock=time.monotonic,
        )
        options.update(overrides)
        return run_groups(groups, analyze, **options)

    def test_never_exceeds_worker_count(self) -> None:
        lock = threading.Lock()
        active = 0
        peak = 0

        def analyze(group, timeout):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.03)
            with lock:
                active -= 1
            return group.representative.relative_path

        for workers in (1, 2, 3):
            with self.subTest(workers=workers):
                peak = 0
                run = self.run_simple(
                    groups_of(*range(1, 8)), analyze, workers=workers
                )
                self.assertEqual(peak, workers)
                self.assertEqual(len(run.finished), 7)
                self.assertEqual(run.not_started, ())

    def test_starts_in_priority_order_with_positions(self) -> None:
        started: list[str] = []

        def analyze(group, timeout):
            return group.representative.relative_path

        messages: list[str] = []
        run = self.run_simple(
            groups_of(500, 10, 200),
            analyze,
            on_file=lambda message: (
                messages.append(message),
                started.append(message) if "started" in message else None,
            ),
        )
        self.assertEqual(
            [m.split(": ")[1].split(" ")[0] for m in started],
            ["f1.dll", "f2.dll", "f0.dll"],
        )
        positions = {item.result: item.position for item in run.finished}
        self.assertEqual(positions, {"f1.dll": 1, "f2.dll": 2, "f0.dll": 3})
        self.assertEqual(len(messages), 6)

    def test_callbacks_run_on_calling_thread(self) -> None:
        threads: set[str] = set()
        self.run_simple(
            groups_of(1, 2, 3, 4),
            lambda group, timeout: None,
            on_file=lambda message: threads.add(threading.current_thread().name),
        )
        self.assertEqual(threads, {threading.current_thread().name})

    def test_budget_stops_new_work_and_caps_timeouts(self) -> None:
        now = [0.0]
        both_running = threading.Barrier(2, timeout=5)
        given: dict[str, float] = {}

        def analyze(group, timeout):
            given[group.representative.relative_path] = timeout
            both_running.wait()
            now[0] = 1000.0
            return None

        run = self.run_simple(
            groups_of(1, 2, 3, 4),
            analyze,
            total_timeout_seconds=250,
            clock=lambda: now[0],
        )
        self.assertEqual(len(run.finished), 2)
        self.assertEqual(len(run.not_started), 2)
        self.assertEqual(set(given.values()), {250.0})

    def test_rejects_zero_workers(self) -> None:
        with self.assertRaises(ValueError):
            self.run_simple(groups_of(1), lambda g, t: None, workers=0)


class BatchTests(unittest.TestCase):
    ENTRIES = [
        entry("small.dll", 300_000),
        entry("OpenAL32.dll", 2_212_352),
        entry("DoorKickers2.exe", 8_557_056),
    ]

    def test_capa_scales_timeouts_and_records_them(self) -> None:
        seen: dict[str, float] = {}

        def run(target, scan_root, *, timeout_seconds, **_):
            relative = target.relative_to(scan_root).as_posix()
            seen[relative] = timeout_seconds
            return capa_result(relative)

        with (
            patch("static_triage.capa.run_capa", side_effect=run),
            tempfile.TemporaryDirectory() as temporary,
        ):
            batch = run_capa_batch(
                self.ENTRIES,
                Path(temporary),
                workers=2,
                file_timeout_seconds=300,
                file_timeout_max_seconds=1800,
            )
        self.assertEqual(seen["small.dll"], 300)
        self.assertAlmostEqual(seen["OpenAL32.dll"], 300 * 2_212_352 / MIB)
        self.assertEqual(seen["DoorKickers2.exe"], 1800)

        payload = batch.to_dict()
        self.assertEqual(payload["workers"], 2)
        self.assertEqual(
            payload["file_timeout_policy"],
            {"base_seconds": 300, "max_seconds": 1800, "reference_bytes": MIB},
        )
        by_path = {r["relative_path"]: r for r in payload["results"]}
        self.assertEqual(by_path["DoorKickers2.exe"]["timeout_seconds"], 1800)
        self.assertEqual(
            [r["relative_path"] for r in payload["results"]],
            sorted(by_path),
        )
        self.assertEqual(
            sorted(r["analysis_position"] for r in payload["results"]),
            [1, 2, 3],
        )

    def test_without_cap_every_file_gets_base(self) -> None:
        seen: list[float] = []

        def run(target, scan_root, *, timeout_seconds, **_):
            seen.append(timeout_seconds)
            return capa_result(target.relative_to(scan_root).as_posix())

        with (
            patch("static_triage.capa.run_capa", side_effect=run),
            tempfile.TemporaryDirectory() as temporary,
        ):
            run_capa_batch(self.ENTRIES, Path(temporary))
        self.assertEqual(seen, [300.0, 300.0, 300.0])

    def test_floss_runs_in_parallel(self) -> None:
        lock = threading.Lock()
        active = 0
        peak = 0

        def run(target, scan_root, **_):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.03)
            with lock:
                active -= 1
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
                duration_seconds=0.03,
                stdout="{}",
                stderr="",
            )

        entries = [entry(f"lib{i}.dll", 1000 + i) for i in range(6)]
        with (
            patch("static_triage.floss.run_floss", side_effect=run),
            tempfile.TemporaryDirectory() as temporary,
        ):
            batch = run_floss_batch(entries, Path(temporary), workers=2)
        self.assertEqual(peak, 2)
        self.assertTrue(batch.complete)
        self.assertEqual(batch.to_dict()["workers"], 2)

    def test_errors_become_results(self) -> None:
        with (
            patch("static_triage.capa.run_capa", side_effect=OSError("boom")),
            tempfile.TemporaryDirectory() as temporary,
        ):
            batch = run_capa_batch(self.ENTRIES[:1], Path(temporary), workers=2)
        self.assertEqual(batch.results[0].status, CapaStatus.ERROR)
        self.assertIn("boom", batch.results[0].error)

    def test_rejects_zero_workers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for batch in (run_capa_batch, run_floss_batch):
                with self.subTest(batch=batch.__name__):
                    with self.assertRaises(ValueError):
                        batch(self.ENTRIES, Path(temporary), workers=0)


class ProfileTests(unittest.TestCase):
    def test_preset_workers(self) -> None:
        expected = {"constrained": 1, "balanced": 2, "high": 4}
        for name, workers in expected.items():
            with self.subTest(preset=name):
                profile = resolve_profile(name)
                self.assertEqual(profile.analysis_workers, workers)
                self.assertEqual(profile.effective_workers, workers)
                self.assertEqual(profile.scan_limits().analysis_workers, workers)

    def test_caps_allow_large_files_more_time(self) -> None:
        for name in PRESETS:
            with self.subTest(preset=name):
                profile = resolve_profile(name)
                self.assertGreater(
                    profile.capa_file_timeout_max_seconds,
                    profile.capa_file_timeout_seconds,
                )
                self.assertGreater(
                    profile.floss_file_timeout_max_seconds,
                    profile.floss_file_timeout_seconds,
                )

    def test_workers_limited_by_cpus(self) -> None:
        profile = resolve_profile("balanced", {"cpus": 1.5})
        self.assertEqual(profile.analysis_workers, 2)
        self.assertEqual(profile.effective_workers, 1)
        self.assertEqual(profile.scan_limits().analysis_workers, 1)

    def test_workers_limited_by_memory(self) -> None:
        profile = resolve_profile(
            "balanced",
            {"cpus": 8, "analysis_workers": 8, "memory_mib": 3072},
        )
        # 3072 MiB minus 512 MiB temporary space fits two analyses.
        self.assertEqual(profile.effective_workers, 2)

    def test_vm_custom_profile(self) -> None:
        profile = resolve_profile(
            "balanced",
            {"cpus": 4, "memory_mib": 6144, "analysis_workers": 4},
        )
        self.assertEqual(profile.effective_workers, 4)

    def test_cap_below_per_file_rejected(self) -> None:
        with self.assertRaises(ResourceProfileError) as raised:
            resolve_profile(
                "balanced",
                {"floss_file_timeout_max_seconds": 300},
            )
        self.assertEqual(
            {field for field, _ in raised.exception.problems},
            {"floss_file_timeout_max_seconds"},
        )

    def test_cap_may_exceed_total_budget(self) -> None:
        profile = resolve_profile(
            "balanced",
            {"capa_file_timeout_max_seconds": 4 * 60 * 60},
        )
        self.assertEqual(profile.capa_file_timeout_max_seconds, 14_400)

    def test_scan_limit_defaults_match_balanced(self) -> None:
        self.assertEqual(resolve_profile("balanced").scan_limits(), ScanLimits())


def minimal_pe() -> bytes:
    data = bytearray(256)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (128).to_bytes(4, "little")
    data[128:132] = b"PE\x00\x00"
    data[150:152] = (0x2000).to_bytes(2, "little")
    return bytes(data)


class ReportTests(unittest.TestCase):
    def test_report_and_summary_show_parallel_settings(self) -> None:
        tools = [ToolInfo(name="capa", executable="/usr/bin/capa", available=True)]
        profile = resolve_profile("balanced")

        def run(target, scan_root, **_):
            return capa_result(
                target.relative_to(scan_root).as_posix(),
                complete=False,
                timed_out=True,
                seconds=300,
            )

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            sample = base / "staging" / "sample"
            sample.mkdir(parents=True)
            (sample / "a.dll").write_bytes(minimal_pe())
            with (
                patch("static_triage.scanner.inspect_tools", return_value=tools),
                patch("static_triage.capa.run_capa", side_effect=run),
            ):
                result = run_inventory_scan_for(base, profile)
            report = json.loads((result.case_directory / "report.json").read_text())
            markdown = result.report_path.read_text()
            summary = summarize(result.case_directory)

        self.assertEqual(report["schema_version"], SCHEMA_VERSION)
        self.assertEqual(SCHEMA_VERSION, "0.2.8")
        self.assertEqual(report["resources"]["workers"], 2)
        self.assertEqual(report["analyzers"]["capa"]["workers"], 2)
        self.assertIn("- Parallel analyses: 2", markdown)
        self.assertIn(
            "- Per-file timeout: 5 min up to 1 MiB, scaling with size up to 30 min",
            markdown,
        )
        self.assertIn("2 parallel", summary)
        self.assertIn("(limit 5 min)", summary)


def run_inventory_scan_for(base: Path, profile):
    from static_triage.scanner import run_inventory_scan

    return run_inventory_scan(
        "sample",
        ScanConfig(
            staging_root=base / "staging",
            results_root=base / "results",
            limits=profile.scan_limits(),
            resource_profile={
                **profile.to_dict(),
                "changed": profile.changed_fields(),
                "effective_workers": profile.effective_workers,
            },
        ),
    )


if __name__ == "__main__":
    unittest.main()