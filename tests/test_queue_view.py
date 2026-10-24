from __future__ import annotations

import contextlib
import io
import json
import time
import unittest
from pathlib import Path

from static_triage.cli import QUEUE_LINE_BUDGET, _print_queue
from static_triage.container.progress import parse_queue_event
from static_triage.deduplication import group_entries_by_sha256
from static_triage.models import EntryKind, EntryState, InventoryEntry, RoutingClass
from static_triage.parallel import run_groups
from static_triage.scheduling import prioritize_groups
from static_triage.web.runtime import ScanRuntime
from static_triage.web.state import WebScanState


def entry(path, size, digest=None):
    return InventoryEntry(
        relative_path=path,
        kind=EntryKind.REGULAR_FILE,
        state=EntryState.INVENTORIED,
        sha256=digest or (path.encode().hex() * 64)[:64],
        size_bytes=size,
        routing_class=RoutingClass.PE_EXECUTABLE,
    )


def item(position, path="a.dll"):
    return {"position": position, "path": path, "size": "1 KB", "copies": 0, "mode": ""}


def printed(stage, items):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        _print_queue(stage, items)
    return out.getvalue().splitlines()


class SchedulerQueueTests(unittest.TestCase):
    def test_planned_order_is_sent_once_up_front(self) -> None:
        same = "d" * 64
        groups = prioritize_groups(group_entries_by_sha256([
            entry("big.exe", 9_000_000),
            entry("v1/steam_api64.dll", 300_000, same),
            entry("v2/steam_api64.dll", 300_000, same),
            entry("a.dll", 10),
        ]))
        seen: list[list[dict]] = []
        run_groups(
            groups, lambda g, t: None, label="FLOSS", workers=1,
            total_timeout_seconds=3600, timeout_for=lambda g: 300.0,
            outcome=lambda r: (True, False, 1.0), clock=time.monotonic,
            detail_for=lambda g: "plain strings" if g.representative.size_bytes > 4_000_000 else None,
            on_queue=seen.append,
        )
        self.assertEqual(len(seen), 1)
        self.assertEqual(
            seen[0],
            [
                {"position": 1, "path": "a.dll", "size": "10 B", "copies": 0, "mode": ""},
                {"position": 2, "path": "v1/steam_api64.dll", "size": "293 KB", "copies": 1, "mode": ""},
                {"position": 3, "path": "big.exe", "size": "8.6 MB", "copies": 0, "mode": "plain strings"},
            ],
        )


class WireFormatTests(unittest.TestCase):
    def test_round_trip_and_chunking(self) -> None:
        items = [item(i, f"folder/{'x' * 150}/file{i}.dll") for i in range(1, 251)]
        lines = printed("capa", items)
        self.assertGreater(len(lines), 1)
        rebuilt = []
        for line in lines:
            self.assertLess(len(line), 8192)
            self.assertLess(len(line), QUEUE_LINE_BUDGET + 400)
            stage, offset, total, chunk = parse_queue_event(line)
            self.assertEqual((stage, total), ("capa", 250))
            self.assertEqual(offset, len(rebuilt))
            rebuilt.extend(chunk)
        self.assertEqual(rebuilt, items)

    def test_rejects_malformed_lines(self) -> None:
        good = json.loads(printed("floss", [item(1)])[0])
        cases = {
            "not json": "{",
            "wrong type": {**good, "type": "progress"},
            "bad stage": {**good, "stage": "clamav"},
            "too many": {**good, "total": 0},
            "bool total": {**good, "total": True},
            "bad position": {**good, "items": [item(5)]},
            "bad mode": {**good, "items": [{**item(1), "mode": "<script>"}]},
            "long path": {**good, "items": [item(1, "x" * 400)]},
            "extra chunk": {**good, "offset": 1},
            "too long": {**good, "items": [item(1)] * 2000},
        }
        for label, payload in cases.items():
            with self.subTest(case=label):
                line = payload if isinstance(payload, str) else json.dumps(payload)
                self.assertIsNone(parse_queue_event(line))

    def test_progress_lines_are_not_queue_lines(self) -> None:
        line = json.dumps({"type": "progress", "stage": "capa", "status": "running", "message": "x"})
        self.assertIsNone(parse_queue_event(line))


class RuntimeQueueTests(unittest.TestCase):
    def runtime(self):
        runtime = ScanRuntime(controller=None)
        runtime._scans["scan-1"] = WebScanState(
            scan_id="scan-1", source_directory="/s", results_directory="/r", state="running",
        )
        return runtime

    def test_files_move_through_the_queue(self) -> None:
        runtime = self.runtime()
        runtime._queue("scan-1", "capa", 0, 4, [item(1, "a.dll"), item(2, "b.dll")])
        runtime._queue("scan-1", "capa", 2, 4, [item(3, "c.exe"), item(4, "d.exe")])
        for message in (
            "capa 1/4 started: a.dll (1 KB)",
            "capa 2/4 started: b.dll (1 KB)",
            "capa 1/4 completed in 19 s: a.dll",
            "capa 2/4 ran out of memory after 14 min 59 s; will retry alone when the other analyses finish: b.dll",
            "capa 3/4 started alone: c.exe (8.0 MB)",
            "capa ignored line",
        ):
            runtime._stage("scan-1", "capa", "running", message)
        queue = runtime.get("scan-1")["queues"]["capa"]
        statuses = [(i["path"], i["status"], i["detail"]) for i in queue["items"]]
        self.assertEqual(
            statuses,
            [
                ("a.dll", "completed", "19 s"),
                ("b.dll", "waiting", "will retry alone"),
                ("c.exe", "running", "alone"),
                ("d.exe", "waiting", ""),
            ],
        )
        runtime._stage("scan-1", "capa", "incomplete", "capa analysis was incomplete.")
        queue = runtime.get("scan-1")["queues"]["capa"]
        self.assertEqual(
            [i["status"] for i in queue["items"]],
            ["completed", "not reached", "not reached", "not reached"],
        )

    def test_plain_strings_and_stops(self) -> None:
        runtime = self.runtime()
        runtime._queue("scan-1", "floss", 0, 2, [item(1, "big.dll"), item(2, "s.dll")])
        runtime._stage("scan-1", "floss", "running", "FLOSS 1/2 started (plain strings): big.dll (49.1 MB)")
        runtime._stage("scan-1", "floss", "running", "FLOSS 1/2 completed in 2 s: big.dll")
        runtime._stage("scan-1", "floss", "running", "FLOSS 2/2 started: s.dll (1 KB)")
        runtime._stage("scan-1", "floss", "running", "FLOSS 2/2 stopped by the user after 1 min 5 s: s.dll")
        items = runtime.get("scan-1")["queues"]["floss"]["items"]
        self.assertEqual((items[0]["status"], items[0]["detail"]), ("completed", "2 s"))
        self.assertEqual((items[1]["status"], items[1]["detail"]), ("stopped", "1 min 5 s"))

    def test_out_of_range_positions_ignored(self) -> None:
        runtime = self.runtime()
        runtime._queue("scan-1", "capa", 0, 1, [item(1)])
        runtime._stage("scan-1", "capa", "running", "capa 9/9 started: x")
        self.assertEqual(runtime.get("scan-1")["queues"]["capa"]["items"][0]["status"], "waiting")


class FrontendTests(unittest.TestCase):
    def test_queue_text_is_never_html(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "frontend/src/ui/queueView.ts").read_text()
        self.assertNotIn("innerHTML", source)
        self.assertNotIn("insertAdjacentHTML", source)


if __name__ == "__main__":
    unittest.main()
