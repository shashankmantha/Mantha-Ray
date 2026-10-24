from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from static_triage.capa import (
    CapaResult,
    CapaStatus,
    _normalize_result,
    run_capa_batch,
)
from static_triage.case_summary import summarize
from static_triage.deduplication import group_entries_by_sha256
from static_triage.floss import FlossResult, FlossStatus, run_floss_batch
from static_triage.models import (
    EntryKind,
    EntryState,
    InventoryEntry,
    RoutingClass,
)
from static_triage.parallel import (
    looks_memory_killed,
    minimum_start_seconds,
    run_groups,
)
from static_triage.reporting import _analysis_plan_lines
from static_triage.runner import CommandResult
from static_triage.scheduling import prioritize_groups

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
        group_entries_by_sha256([entry(name, size) for name, size in sizes.items()])
    )


class Tracker:
    """Counts concurrent analyses and records how busy each run was."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.active = 0
        self.calls: dict[str, int] = {}
        self.alone: dict[str, list[bool]] = {}

    def enter(self, name: str) -> int:
        with self.lock:
            self.active += 1
            self.calls[name] = self.calls.get(name, 0) + 1
            self.alone.setdefault(name, []).append(self.active == 1)
            return self.calls[name]

    def leave(self) -> None:
        with self.lock:
            self.active -= 1


def run(groups, analyze, **overrides):
    options = dict(
        label="capa",
        workers=2,
        total_timeout_seconds=3600,
        timeout_for=lambda group: 300.0,
        outcome=lambda result: (result == "ok", False, 1.0),
        clock=time.monotonic,
        retry_alone_if=lambda result: result == "killed",
    )
    options.update(overrides)
    return run_groups(groups, analyze, **options)


class MemoryRetryTests(unittest.TestCase):
    def test_killed_while_sharing_is_retried_alone(self) -> None:
        tracker = Tracker()
        both_running = threading.Barrier(2, timeout=5)

        def analyze(group, timeout):
            name = group.representative.relative_path
            call = tracker.enter(name)
            try:
                if call == 1:
                    both_running.wait()
                    if name == "game.exe":
                        return "killed"
                    time.sleep(0.05)
                return "ok"
            finally:
                tracker.leave()

        messages: list[str] = []
        result = run(
            groups_of(**{"small.dll": 10, "game.exe": 8 * MIB}),
            analyze,
            on_file=messages.append,
        )

        self.assertEqual(tracker.calls["game.exe"], 2)
        self.assertEqual(tracker.alone["game.exe"][1], True)
        by_name = {
            item.group.representative.relative_path: item
            for item in result.finished
        }
        self.assertEqual(len(result.finished), 2)
        self.assertEqual(by_name["game.exe"].result, "ok")
        self.assertEqual(by_name["game.exe"].first_attempt, "killed")
        self.assertEqual(by_name["game.exe"].position, 2)
        self.assertIsNone(by_name["small.dll"].first_attempt)
        self.assertTrue(any("ran out of memory" in m for m in messages))
        self.assertIn("capa 2/2 started alone: game.exe (8.0 MB)", messages)

    def test_retry_blocks_new_work_until_done(self) -> None:
        tracker = Tracker()
        both_running = threading.Barrier(2, timeout=5)
        order: list[str] = []

        def analyze(group, timeout):
            name = group.representative.relative_path
            call = tracker.enter(name)
            try:
                order.append(f"{name}#{call}")
                if name in ("a.dll", "b.dll") and call == 1:
                    both_running.wait()
                    if name == "b.dll":
                        return "killed"
                    # a.dll finishes after b.dll's kill has been seen, as in
                    # the real case this tests; otherwise c.dll may already
                    # have started before anything was known about b.dll.
                    time.sleep(0.3)
                    return "ok"
                return "ok"
            finally:
                tracker.leave()

        run(groups_of(**{"a.dll": 10, "b.dll": 20, "c.dll": 30}), analyze)
        self.assertLess(order.index("b.dll#2"), order.index("c.dll#1"))
        self.assertTrue(tracker.alone["b.dll"][1])

    def test_no_retry_with_one_worker(self) -> None:
        calls: list[str] = []

        def analyze(group, timeout):
            calls.append(group.representative.relative_path)
            return "killed"

        result = run(groups_of(**{"a.dll": 10}), analyze, workers=1)
        self.assertEqual(calls, ["a.dll"])
        self.assertIsNone(result.finished[0].first_attempt)

    def test_retried_only_once(self) -> None:
        tracker = Tracker()
        both_running = threading.Barrier(2, timeout=5)

        def analyze(group, timeout):
            name = group.representative.relative_path
            call = tracker.enter(name)
            try:
                if call == 1:
                    both_running.wait()
                return "killed" if name == "game.exe" else "ok"
            finally:
                tracker.leave()

        result = run(groups_of(**{"a.dll": 10, "game.exe": 8 * MIB}), analyze)
        self.assertEqual(tracker.calls["game.exe"], 2)
        final = [i for i in result.finished if i.result == "killed"]
        self.assertEqual(len(final), 1)
        self.assertEqual(final[0].first_attempt, "killed")

    def test_no_time_to_retry_keeps_first_attempt(self) -> None:
        now = [0.0]
        both_running = threading.Barrier(2, timeout=5)
        calls: list[str] = []

        def analyze(group, timeout):
            name = group.representative.relative_path
            calls.append(name)
            both_running.wait()
            now[0] = 3590.0
            return "killed" if name == "game.exe" else "ok"

        messages: list[str] = []
        result = run(
            groups_of(**{"a.dll": 10, "game.exe": 8 * MIB}),
            analyze,
            clock=lambda: now[0],
            on_file=messages.append,
        )
        self.assertEqual(sorted(calls), ["a.dll", "game.exe"])
        killed = [i for i in result.finished if i.result == "killed"]
        self.assertEqual(len(killed), 1)
        self.assertIsNone(killed[0].first_attempt)
        self.assertTrue(any("failed after" in m for m in messages))


class StartRuleTests(unittest.TestCase):
    def test_minimum(self) -> None:
        self.assertEqual(minimum_start_seconds(1800, 3600), 450)
        self.assertEqual(minimum_start_seconds(300, 3600), 75)
        self.assertEqual(minimum_start_seconds(100, 3600), 60)
        self.assertEqual(minimum_start_seconds(30, 3600), 30)
        self.assertEqual(minimum_start_seconds(300, 10), 5)

    def test_file_without_enough_budget_is_not_started(self) -> None:
        # Tonight's case: 46 s left for a file with a 30 min limit.
        now = [0.0]
        started: list[str] = []

        def analyze(group, timeout):
            started.append(group.representative.relative_path)
            now[0] += 3554.0
            return "ok"

        result = run(
            groups_of(**{"small.dll": 10, "game.exe": 8 * MIB}),
            analyze,
            workers=1,
            clock=lambda: now[0],
            timeout_for=lambda g: 1800.0 if g.representative.size_bytes > MIB else 300.0,
        )
        self.assertEqual(started, ["small.dll"])
        self.assertEqual(
            [g.representative.relative_path for g in result.not_started],
            ["game.exe"],
        )

    def test_memory_kill_codes(self) -> None:
        self.assertTrue(looks_memory_killed(-9, False))
        self.assertTrue(looks_memory_killed(137, False))
        self.assertFalse(looks_memory_killed(-9, True))
        self.assertFalse(looks_memory_killed(1, False))
        self.assertFalse(looks_memory_killed(-15, False))


def capa_result(relative, *, rc=0, timed_out=False, seconds=1.0):
    ok = rc == 0 and not timed_out
    return CapaResult(
        status=(
            CapaStatus.COMPLETED if ok
            else CapaStatus.TIMED_OUT if timed_out
            else CapaStatus.ERROR
        ),
        complete=ok,
        relative_path=relative,
        return_code=rc,
        capabilities=(),
        timed_out=timed_out,
        output_truncated=False,
        duration_seconds=seconds,
        stdout="{}" if ok else "",
        stderr="",
        error=None if ok else "x",
    )


class BatchTests(unittest.TestCase):
    def test_capa_retry_recorded_in_report(self) -> None:
        both_running = threading.Barrier(2, timeout=5)
        calls: dict[str, int] = {}
        lock = threading.Lock()

        def fake(target, scan_root, *, timeout_seconds, **_):
            name = target.relative_to(scan_root).as_posix()
            with lock:
                calls[name] = calls.get(name, 0) + 1
                call = calls[name]
            if call == 1:
                both_running.wait()
                if name == "DoorKickers2.exe":
                    return capa_result(name, rc=-9, seconds=899.0)
            return capa_result(name, seconds=600.0)

        with (
            patch("static_triage.capa.run_capa", side_effect=fake),
            tempfile.TemporaryDirectory() as temporary,
        ):
            batch = run_capa_batch(
                [entry("OpenAL32.dll", 2_212_352), entry("DoorKickers2.exe", 8_557_056)],
                Path(temporary),
                workers=2,
                file_timeout_max_seconds=1800,
            )
        self.assertTrue(batch.complete)
        payload = batch.to_dict()
        dk = next(r for r in payload["results"] if r["relative_path"] == "DoorKickers2.exe")
        self.assertTrue(dk["retried_alone"])
        self.assertEqual(dk["first_attempt"]["return_code"], -9)
        self.assertEqual(dk["first_attempt"]["duration_seconds"], 899.0)
        self.assertTrue(dk["complete"])
        self.assertEqual(payload["attempted_files"], 2)
        lines = _analysis_plan_lines(payload)
        self.assertIn("- Retried alone after running out of memory: 1", lines)

    def test_budget_cut_is_labelled(self) -> None:
        now = [0.0]

        def fake(target, scan_root, *, timeout_seconds, **_):
            name = target.relative_to(scan_root).as_posix()
            now[0] += timeout_seconds if name == "big.exe" else 3000.0
            return capa_result(
                name,
                timed_out=name == "big.exe",
                seconds=timeout_seconds if name == "big.exe" else 3000.0,
            )

        with (
            patch("static_triage.capa.run_capa", side_effect=fake),
            patch("static_triage.capa.time.monotonic", side_effect=lambda: now[0]),
            tempfile.TemporaryDirectory() as temporary,
        ):
            batch = run_capa_batch(
                [entry("small.dll", 10), entry("big.exe", 8 * MIB)],
                Path(temporary),
                file_timeout_max_seconds=1800,
            )
        big = next(r for r in batch.results if r.relative_path == "big.exe")
        self.assertTrue(big.stopped_at_budget_end)
        self.assertEqual(big.timeout_seconds, 600)
        self.assertIn("stopped at the end of the time budget", batch.error)

    def test_memory_kill_message(self) -> None:
        execution = CommandResult(
            command=("capa",),
            return_code=-9,
            stdout="",
            stderr="",
            timed_out=False,
            output_truncated=False,
            duration_seconds=899.0,
        )
        result = _normalize_result(execution, "DoorKickers2.exe")
        self.assertEqual(result.status, CapaStatus.ERROR)
        self.assertIn("ran out of memory", result.error)

    def test_floss_retries_too(self) -> None:
        both_running = threading.Barrier(2, timeout=5)
        calls: dict[str, int] = {}
        lock = threading.Lock()

        def fake(target, scan_root, **_):
            name = target.relative_to(scan_root).as_posix()
            with lock:
                calls[name] = calls.get(name, 0) + 1
                call = calls[name]
            if call == 1:
                both_running.wait()
            killed = name == "steam_api64.dll" and call == 1
            return FlossResult(
                status=FlossStatus.ERROR if killed else FlossStatus.COMPLETED,
                complete=not killed,
                relative_path=name,
                return_code=-9 if killed else 0,
                strings=(),
                total_strings=0,
                strings_truncated=False,
                timed_out=False,
                output_truncated=False,
                duration_seconds=1.0,
                stdout="{}",
                stderr="",
            )

        with (
            patch("static_triage.floss.run_floss", side_effect=fake),
            tempfile.TemporaryDirectory() as temporary,
        ):
            batch = run_floss_batch(
                [entry("steam_api.dll", 300_000), entry("steam_api64.dll", 310_000)],
                Path(temporary),
                workers=2,
            )
        self.assertEqual(calls["steam_api64.dll"], 2)
        self.assertTrue(batch.complete)


class SummaryTests(unittest.TestCase):
    def test_summary_labels(self) -> None:
        report = {
            "status": "incomplete",
            "analyzers": {
                "capa": {
                    "unique_eligible_files": 3,
                    "results": [
                        {"relative_path": "a.exe", "complete": True,
                         "timed_out": False, "duration_seconds": 1500,
                         "analysis_position": 1, "retried_alone": True,
                         "return_code": 0},
                        {"relative_path": "b.exe", "complete": False,
                         "timed_out": True, "duration_seconds": 46,
                         "analysis_position": 2, "timeout_seconds": 46,
                         "stopped_at_budget_end": True},
                        {"relative_path": "c.exe", "complete": False,
                         "timed_out": False, "duration_seconds": 899,
                         "analysis_position": 3, "timeout_seconds": 1800,
                         "return_code": -9},
                    ],
                },
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            case = Path(temporary) / "case-20261021T005527Z-45214b4a"
            case.mkdir()
            (case / "report.json").write_text(json.dumps(report))
            text = summarize(case)
        self.assertIn("1 completed", text)
        self.assertIn("0 timed out", text)
        self.assertIn("1 stopped at budget end", text)
        self.assertIn("1 failed", text)
        self.assertIn("1 retried alone", text)
        self.assertIn("retried alone after running out of memory", text)
        self.assertIn("budget ran out", text)
        self.assertIn("out of memory)", text)


if __name__ == "__main__":
    unittest.main()