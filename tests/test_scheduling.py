from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from static_triage.capa import (
    CapaResult,
    CapaStatus,
    run_capa_batch,
    select_capa_entries,
)
from static_triage.deduplication import group_entries_by_sha256
from static_triage.floss import (
    FlossResult,
    FlossStatus,
    run_floss_batch,
    select_floss_entries,
)
from static_triage.models import (
    EntryKind,
    EntryState,
    InventoryEntry,
    RoutingClass,
)
from static_triage.scheduling import (
    SCHEDULING_POLICY,
    in_path_order,
    prioritize_groups,
)

MIB = 1024**2


def entry(path, size, digest=None, routing=RoutingClass.PE_EXECUTABLE):
    return InventoryEntry(
        relative_path=path,
        kind=EntryKind.REGULAR_FILE,
        state=EntryState.INVENTORIED,
        sha256=digest if digest is not None else f"{abs(hash(path)):064x}"[:64],
        size_bytes=size,
        routing_class=routing,
    )


# A cut-down Door Kickers 2: big third-party libraries that time out,
# and the small crack files that finish quickly.
DOOR_KICKERS = [
    entry("ConfigTool.dll", 220_000),
    entry("DoorKickers2.exe", 8_557_056),
    entry("OpenAL32.dll", 2_212_352),
    entry("avcodec-59.dll", 51_487_232),
    entry("avfilter-8.dll", 19_397_632),
    entry("avformat-59.dll", 12_451_328),
    entry("steam_api64.dll", 300_000),
    entry("steam_api64.rne", 290_000),
]


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now


def fake_analyzer(result_type, status_ok, status_timeout, clock, order):
    """Small files finish in 60 s; files over 1 MiB use the full timeout."""

    def run(target, scan_root, *, timeout_seconds, **_):
        relative = target.relative_to(scan_root).as_posix()
        order.append(relative)
        size = next(e.size_bytes for e in DOOR_KICKERS if e.relative_path == relative)
        slow = size > MIB
        spent = timeout_seconds if slow else min(60.0, timeout_seconds)
        clock.now += spent
        common = dict(
            complete=not slow,
            relative_path=relative,
            return_code=-15 if slow else 0,
            timed_out=slow,
            output_truncated=False,
            duration_seconds=spent,
            stdout="",
            stderr="",
        )
        if result_type is CapaResult:
            return CapaResult(
                status=status_timeout if slow else status_ok,
                capabilities=(),
                **common,
            )
        return FlossResult(
            status=status_timeout if slow else status_ok,
            strings=(),
            total_strings=0,
            strings_truncated=False,
            **common,
        )

    return run


class PriorityTests(unittest.TestCase):
    def test_smallest_first_with_path_tiebreak(self) -> None:
        groups = group_entries_by_sha256(
            [
                entry("b.dll", 100),
                entry("a.dll", 100),
                entry("big.exe", 5_000),
                entry("tiny.dll", 10),
            ]
        )
        ordered = [g.representative.relative_path for g in prioritize_groups(groups)]
        self.assertEqual(ordered, ["tiny.dll", "a.dll", "b.dll", "big.exe"])

    def test_unknown_sizes_go_last(self) -> None:
        groups = group_entries_by_sha256(
            [entry("unknown.dll", None), entry("huge.exe", 10**9)]
        )
        ordered = [g.representative.relative_path for g in prioritize_groups(groups)]
        self.assertEqual(ordered, ["huge.exe", "unknown.dll"])

    def test_bool_size_treated_as_unknown(self) -> None:
        groups = group_entries_by_sha256(
            [entry("flag.dll", True), entry("real.dll", 5)]
        )
        ordered = [g.representative.relative_path for g in prioritize_groups(groups)]
        self.assertEqual(ordered, ["real.dll", "flag.dll"])

    def test_order_is_deterministic(self) -> None:
        shuffled = list(reversed(DOOR_KICKERS))
        first = prioritize_groups(group_entries_by_sha256(DOOR_KICKERS))
        second = prioritize_groups(group_entries_by_sha256(shuffled))
        self.assertEqual(
            [g.representative.relative_path for g in first],
            [g.representative.relative_path for g in second],
        )

    def test_duplicates_stay_grouped(self) -> None:
        same = "f" * 64
        groups = prioritize_groups(
            group_entries_by_sha256(
                [
                    entry("v1/steam_api.dll", 300, same),
                    entry("v2/steam_api.dll", 300, same),
                    entry("big.exe", 10_000),
                ]
            )
        )
        self.assertEqual(len(groups), 2)
        self.assertEqual(groups[0].reused_paths, ("v2/steam_api.dll",))

    def test_in_path_order(self) -> None:
        results = [SimpleNamespace(relative_path=p) for p in ("b", "a", "c")]
        self.assertEqual(
            [r.relative_path for r in in_path_order(results)],
            ["a", "b", "c"],
        )


class SelectionTests(unittest.TestCase):
    def test_file_cap_keeps_smallest(self) -> None:
        for select in (select_capa_entries, select_floss_entries):
            with self.subTest(select=select.__name__):
                selection = select(DOOR_KICKERS, max_files=3)
                chosen = {e.relative_path for e in selection.entries}
                smallest = {"ConfigTool.dll", "steam_api64.dll", "steam_api64.rne"}
                if select is select_capa_entries:
                    self.assertEqual(chosen, smallest)
                    self.assertEqual(selection.skipped_due_to_limit, 5)
                else:
                    # FLOSS gives files over its emulation limit a quick
                    # plain-strings pass outside the cap; only OpenAL32.dll
                    # (2.2 MB, still emulated) is capped.
                    big = {
                        "DoorKickers2.exe", "avcodec-59.dll",
                        "avfilter-8.dll", "avformat-59.dll",
                    }
                    self.assertEqual(chosen, smallest | big)
                    self.assertEqual(selection.skipped_due_to_limit, 1)


class BatchSchedulingTests(unittest.TestCase):
    def run_batch(self, analyzer):
        clock = FakeClock()
        order: list[str] = []
        if analyzer == "capa":
            fake = fake_analyzer(
                CapaResult, CapaStatus.COMPLETED, CapaStatus.TIMED_OUT, clock, order
            )
            target = "static_triage.capa"
            runner, batch = "run_capa", run_capa_batch
        else:
            fake = fake_analyzer(
                FlossResult, FlossStatus.COMPLETED, FlossStatus.TIMED_OUT, clock, order
            )
            target = "static_triage.floss"
            runner, batch = "run_floss", run_floss_batch
        with (
            patch(f"{target}.{runner}", side_effect=fake),
            patch(f"{target}.time", SimpleNamespace(monotonic=clock.monotonic)),
            tempfile.TemporaryDirectory() as temporary,
        ):
            result = batch(
                DOOR_KICKERS,
                Path(temporary),
                max_files=50,
                file_timeout_seconds=300,
                total_timeout_seconds=600,
            )
        return result, order

    def test_small_crack_files_analyzed_before_budget_runs_out(self) -> None:
        for analyzer in ("capa", "floss"):
            with self.subTest(analyzer=analyzer):
                result, order = self.run_batch(analyzer)
                # 3 small files (180 s), then one big file eats the rest.
                self.assertEqual(
                    order[:3],
                    ["ConfigTool.dll", "steam_api64.rne", "steam_api64.dll"],
                )
                done = {r.relative_path for r in result.results if r.complete}
                self.assertIn("steam_api64.dll", done)
                self.assertIn("steam_api64.rne", done)
                self.assertNotIn("avcodec-59.dll", order)

    def test_alphabetical_order_would_have_missed_them(self) -> None:
        # The old order reached the crack files only after four large
        # files, which would exhaust a 600 s budget at 300 s each.
        alphabetical = sorted(e.relative_path for e in DOOR_KICKERS)
        before_crack = alphabetical[: alphabetical.index("steam_api64.dll")]
        big = [p for p in before_crack if any(
            e.relative_path == p and e.size_bytes > MIB for e in DOOR_KICKERS
        )]
        self.assertGreaterEqual(len(big) * 300, 600)

    def test_results_reported_in_path_order_with_positions(self) -> None:
        for analyzer in ("capa", "floss"):
            with self.subTest(analyzer=analyzer):
                result, order = self.run_batch(analyzer)
                paths = [r.relative_path for r in result.results]
                self.assertEqual(paths, sorted(paths))
                positions = {
                    r.relative_path: r.analysis_position for r in result.results
                }
                # FLOSS runs its quick plain-strings pass on big files
                # first; the fake analyzer only records emulated files.
                plain = sum(
                    getattr(r, "mode", "emulation") == "plain"
                    for r in result.results
                )
                for index, path in enumerate(order, start=1 + plain):
                    self.assertEqual(positions[path], index)
                payload = result.to_dict()
                self.assertEqual(payload["scheduling_policy"], SCHEDULING_POLICY)
                self.assertIn("analysis_position", payload["results"][0])


if __name__ == "__main__":
    unittest.main()


class ReportTests(unittest.TestCase):
    def test_report_records_policy_and_positions(self) -> None:
        import json

        from static_triage.capa import CapaBatchResult, CapaBatchStatus
        from static_triage.config import ScanConfig
        from static_triage.models import ToolInfo
        from static_triage.scanner import run_inventory_scan

        capa_result = CapaBatchResult(
            status=CapaBatchStatus.COMPLETED,
            complete=True,
            eligible_files=1,
            attempted_files=1,
            skipped_due_to_limit=0,
            skipped_due_to_timeout=0,
            results=(
                CapaResult(
                    status=CapaStatus.COMPLETED,
                    complete=True,
                    relative_path="sample/app.exe",
                    return_code=0,
                    capabilities=(),
                    timed_out=False,
                    output_truncated=False,
                    duration_seconds=1.0,
                    stdout="{}",
                    stderr="",
                    analysis_position=1,
                ),
            ),
            duration_seconds=1.0,
        )
        tools = [
            ToolInfo(name="capa", executable="/usr/bin/capa", available=True)
        ]
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            sample = base / "staging" / "sample"
            sample.mkdir(parents=True)
            (sample / "app.exe").write_bytes(b"MZ" + b"\0" * 64)
            with (
                patch("static_triage.scanner.inspect_tools", return_value=tools),
                patch(
                    "static_triage.scanner.run_capa_batch",
                    return_value=capa_result,
                ),
            ):
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
            markdown = result.report_path.read_text()

        capa = report["analyzers"]["capa"]
        self.assertEqual(capa["scheduling_policy"], "smallest-first")
        self.assertEqual(capa["results"][0]["analysis_position"], 1)
        self.assertIn("Analysis order: smallest files first", markdown)
        self.assertTrue(report["schema_version"].startswith("0.2."))