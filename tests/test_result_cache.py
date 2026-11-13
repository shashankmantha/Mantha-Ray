from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from static_triage import result_cache
from static_triage.capa import (
    CapaBatchResult, CapaBatchStatus, CapaCapability, CapaResult, CapaStatus,
    run_capa_batch, select_capa_entries,
)
from static_triage.container.command import DockerScanRequest, build_docker_command
from static_triage.floss import EMULATION, PLAIN, FlossResult, FlossStatus, FlossString, run_floss_batch
from static_triage.integrity import verify_hashes
from static_triage.models import EntryKind, EntryState, InventoryEntry, RoutingClass

CASE = "case-20261108T230221Z-8be2f61c"
CAPA_VERSION = "capa 9.2.1"
FLOSS_VERSION = "floss 3.1.1"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def timed_out_result(path: str, limit: float = 960.0, **changes) -> CapaResult:
    return replace(
        capa_result(path, complete=False),
        timeout_seconds=limit, duration_seconds=limit, **changes,
    )


def capa_result(path: str, complete: bool = True, **changes) -> CapaResult:
    result = CapaResult(
        status=CapaStatus.COMPLETED if complete else CapaStatus.TIMED_OUT,
        complete=complete, relative_path=path, return_code=0 if complete else -9,
        capabilities=(
            CapaCapability("read file on Windows", "host-interaction/file-system/read", 3, ("T1005",), ()),
            CapaCapability("encode data using XOR", "data-manipulation/encoding/xor", 1, (), ("C0026.002",)),
        ) if complete else (),
        timed_out=not complete, output_truncated=False, duration_seconds=1920.5,
        stdout="", stderr="", peak_memory_mib=4600.0,
    )
    return replace(result, **changes)


def floss_result(path: str, mode: str = EMULATION) -> FlossResult:
    return FlossResult(
        status=FlossStatus.COMPLETED, complete=True, relative_path=path, return_code=0,
        strings=(FlossString("decoded", "http://example.invalid/a", "utf-16le", False, "url"),),
        total_strings=40, strings_truncated=False, timed_out=False, output_truncated=False,
        duration_seconds=12.0, stdout="", stderr="", mode=mode, fully_scanned=True,
    )


def batch(results) -> dict:
    return CapaBatchResult(
        status=CapaBatchStatus.PARTIAL, complete=False, eligible_files=len(results),
        attempted_files=len(results), skipped_due_to_limit=0, skipped_due_to_timeout=0,
        results=tuple(results), duration_seconds=1.0,
    ).to_dict()


def write_case(results_dir: Path, files: dict[str, str], capa: list, floss: list,
               case_id: str = CASE) -> Path:
    case = results_dir / case_id
    case.mkdir(parents=True)
    with (case / "files.jsonl").open("w") as handle:
        for path, digest in files.items():
            handle.write(json.dumps({
                "relative_path": path, "kind": "regular_file", "state": "inventoried",
                "sha256": digest,
            }) + "\n")
    manifest = {
        "case_id": case_id,
        "completed_at": "2026-11-08T23:02:21+00:00",
        "tools": [
            {"name": "capa", "version": CAPA_VERSION, "available": True},
            {"name": "floss", "version": FLOSS_VERSION, "available": True},
        ],
        "limits": {"floss_max_strings": 2000, "floss_max_string_chars": 4096},
    }
    (case / "manifest.json").write_text(json.dumps(manifest))
    report = {
        "case_id": case_id,
        "analyzers": {
            "capa": batch(capa),
            "floss": {"results": [result.to_dict() for result in floss]},
        },
    }
    (case / "report.json").write_text(json.dumps(report))
    return case


def entry(path: str, digest: str, size: int = 1000) -> InventoryEntry:
    return InventoryEntry(
        relative_path=path, kind=EntryKind.REGULAR_FILE, state=EntryState.INVENTORIED,
        sha256=digest, size_bytes=size, routing_class=RoutingClass.PE_EXECUTABLE,
    )


class CacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        self.cache = self.root / "cache"
        self.results = self.root / "results"
        self.files = {
            "v1/DoorKickers2.exe": sha("game"),
            "v1/steam_api64.dll": sha("steam"),
            "v1/avcodec-59.dll": sha("ffmpeg"),
            "copy/DoorKickers2.exe": sha("game"),
        }

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def ingest(self, **kwargs) -> int:
        case = write_case(self.results, self.files, **kwargs)
        return result_cache.ingest_case(case, self.cache)

    def test_only_complete_results_of_listed_files_are_saved(self) -> None:
        added = self.ingest(
            capa=[
                capa_result("v1/DoorKickers2.exe", reused_for=("copy/DoorKickers2.exe",)),
                capa_result("v1/avcodec-59.dll", complete=False),       # timed out
                capa_result("not/in/files.jsonl.exe"),                  # unknown path
                capa_result("v1/steam_api64.dll", cached_from={"case_id": CASE}),  # already cached
            ],
            floss=[floss_result("v1/DoorKickers2.exe"), floss_result("v1/steam_api64.dll", PLAIN)],
        )
        # Two results saved; the timed-out file is noted instead, not saved.
        self.assertEqual(added, (2, 1))
        self.assertEqual(result_cache.status(self.cache)["entries"], {"capa": 1, "floss": 1})
        # The same case is never read twice.
        self.assertEqual(result_cache.ingest_case(self.results / CASE, self.cache), (0, 0))
        self.assertFalse(result_cache.ingest_case(self.results / CASE, self.cache))

    def test_round_trip(self) -> None:
        self.ingest(capa=[capa_result("v1/DoorKickers2.exe")], floss=[floss_result("v1/DoorKickers2.exe")])
        found = result_cache.load_capa(self.cache, [sha("game"), sha("other")], tool_version=CAPA_VERSION)
        self.assertEqual(list(found), [sha("game")])
        cached = found[sha("game")]
        self.assertTrue(cached.complete)
        self.assertEqual(cached.capabilities, capa_result("x").capabilities)
        self.assertEqual(cached.cached_from["case_id"], CASE)
        self.assertEqual(cached.cached_from["duration_seconds"], 1920.5)
        self.assertEqual(cached.cached_from["relative_path"], "v1/DoorKickers2.exe")
        strings = result_cache.load_floss(
            self.cache, [sha("game")], tool_version=FLOSS_VERSION, max_strings=2000, max_string_chars=4096,
        )[sha("game")]
        self.assertEqual(strings.strings, floss_result("x").strings)
        self.assertEqual((strings.total_strings, strings.mode), (40, EMULATION))

    def test_different_tool_version_or_limits_are_not_reused(self) -> None:
        self.ingest(capa=[capa_result("v1/DoorKickers2.exe")], floss=[floss_result("v1/DoorKickers2.exe")])
        self.assertEqual(result_cache.load_capa(self.cache, [sha("game")], tool_version="capa 9.3.0"), {})
        self.assertEqual(result_cache.load_capa(self.cache, [sha("game")], tool_version=None), {})
        self.assertEqual(result_cache.load_floss(
            self.cache, [sha("game")], tool_version=FLOSS_VERSION, max_strings=500, max_string_chars=4096,
        ), {})

    def test_tampered_or_misplaced_entries_are_ignored(self) -> None:
        self.ingest(capa=[capa_result("v1/DoorKickers2.exe")], floss=[])
        path = result_cache.entry_path(self.cache, "capa", sha("game"))
        good = json.loads(path.read_text())
        cases = {
            "other file's entry": {**good, "sha256": sha("steam")},
            "bad capability": {**good, "capabilities": [{"name": 5}]},
            "unknown schema": {**good, "schema": 99},
            "bad case id": {**good, "case_id": "../../etc"},
        }
        for label, data in cases.items():
            with self.subTest(case=label):
                path.write_text(json.dumps(data))
                self.assertEqual(
                    result_cache.load_capa(self.cache, [sha("game")], tool_version=CAPA_VERSION), {},
                )
        path.write_text("not json")
        self.assertEqual(result_cache.load_capa(self.cache, [sha("game")], tool_version=CAPA_VERSION), {})
        # A missing cache folder just means nothing to reuse.
        self.assertEqual(result_cache.load_capa(self.root / "none", [sha("game")], tool_version=CAPA_VERSION), {})
        self.assertEqual(result_cache.load_capa(None, [sha("game")], tool_version=CAPA_VERSION), {})

    def test_results_folder_ingest_catches_up_and_skips_junk(self) -> None:
        write_case(self.results, self.files, [capa_result("v1/DoorKickers2.exe")], [])
        write_case(self.results, self.files, [capa_result("v1/steam_api64.dll")], [],
                   case_id="case-20261109T010000Z-00000001")
        (self.results / "not-a-case").mkdir()
        (self.results / "case-20261109T020000Z-00000002").symlink_to(self.results / CASE)
        self.assertEqual(result_cache.ingest_results_directory(self.results, self.cache).results, 2)
        self.assertFalse(result_cache.ingest_results_directory(self.results, self.cache))

    def test_clear_keeps_old_cases_out(self) -> None:
        self.ingest(capa=[capa_result("v1/DoorKickers2.exe")], floss=[])
        self.assertEqual(result_cache.clear(self.cache), 1)
        self.assertFalse(result_cache.ingest_results_directory(self.results, self.cache))
        self.assertEqual(result_cache.status(self.cache)["entries"], {"capa": 0, "floss": 0})


class IngestMessageTests(unittest.TestCase):
    """The scan log must say what was learned, results or timeouts."""

    def test_summary_mentions_both_kinds(self) -> None:
        from static_triage.container.controller import _ingest_summary

        counts = result_cache.IngestCounts
        self.assertEqual(_ingest_summary(counts(2, 0)),
                         "2 capa/FLOSS results saved for reuse on identical files")
        self.assertEqual(_ingest_summary(counts(0, 1)),
                         "1 file that ran out of time noted for a larger limit")
        self.assertIn(" and ", _ingest_summary(counts(3, 8)))
        self.assertEqual(_ingest_summary(counts(0, 0)), "nothing new")


class TimeoutEscalationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        self.cache = self.root / "cache"
        self.results = self.root / "results"
        self.files = {"bin/steamclient.dll": sha("sc"), "bin/ok.dll": sha("ok")}

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_timeouts_are_remembered_and_escalate(self) -> None:
        write_case(self.results, self.files,
                   [timed_out_result("bin/steamclient.dll"), capa_result("bin/ok.dll")], [])
        result_cache.ingest_case(self.results / CASE, self.cache)
        hints = result_cache.load_more_time(self.cache, "capa", self.files.values())
        self.assertEqual(hints, {sha("sc"): 1})
        # The same case never counts twice; a second case does.
        result_cache.ingest_case(self.results / CASE, self.cache)
        write_case(self.results, self.files, [timed_out_result("bin/steamclient.dll")], [],
                   case_id="case-20261111T010000Z-00000002")
        result_cache.ingest_case(self.results / "case-20261111T010000Z-00000002", self.cache)
        hints = result_cache.load_more_time(self.cache, "capa", self.files.values())
        self.assertEqual(hints, {sha("sc"): 2})
        self.assertEqual(result_cache.load_more_time(self.cache, "floss", self.files.values()), {})

    def test_budget_stops_and_user_stops_do_not_escalate(self) -> None:
        write_case(self.results, self.files, [
            timed_out_result("bin/steamclient.dll", stopped_at_budget_end=True),
            timed_out_result("bin/ok.dll", stopped_by_user=True),
        ], [])
        result_cache.ingest_case(self.results / CASE, self.cache)
        self.assertEqual(result_cache.load_more_time(self.cache, "capa", self.files.values()), {})

    def test_escalated_timeout_doubles_then_caps(self) -> None:
        self.assertEqual(result_cache.escalated_timeout(600, 0), 600)
        self.assertEqual(result_cache.escalated_timeout(600, 1), 1200)
        self.assertEqual(result_cache.escalated_timeout(600, 2), 2400)
        self.assertEqual(result_cache.escalated_timeout(600, 9), 2400)
        self.assertEqual(result_cache.escalated_timeout(5000, 1), 7200)

    def test_completion_after_escalation_is_cached_and_clear_resets(self) -> None:
        write_case(self.results, self.files, [timed_out_result("bin/steamclient.dll")], [])
        result_cache.ingest_case(self.results / CASE, self.cache)
        write_case(self.results, self.files, [capa_result("bin/steamclient.dll")], [],
                   case_id="case-20261111T020000Z-00000003")
        result_cache.ingest_case(self.results / "case-20261111T020000Z-00000003", self.cache)
        self.assertEqual(
            list(result_cache.load_capa(self.cache, [sha("sc")], tool_version=CAPA_VERSION)),
            [sha("sc")],
        )
        result_cache.clear(self.cache)
        self.assertEqual(result_cache.load_more_time(self.cache, "capa", self.files.values()), {})

    def test_batch_uses_the_larger_limit(self) -> None:
        entries = [entry("bin/steamclient.dll", sha("sc"), size=4 * 1024**2)]
        captured = {}

        def fake_run_groups(groups, analyze, *, timeout_for, **kwargs):
            captured["timeout"] = timeout_for(groups[0])
            raise SystemExit  # stop before running anything

        from unittest.mock import patch as mock_patch
        for attempts, expected in ((0, 1200.0), (1, 2400.0)):
            with mock_patch("static_triage.capa.run_groups", side_effect=fake_run_groups):
                with self.assertRaises(SystemExit):
                    run_capa_batch(
                        entries, Path("/nonexistent"), executable="/nonexistent/capa",
                        file_timeout_seconds=300.0, file_timeout_max_seconds=3600.0,
                        more_time={sha("sc"): attempts} if attempts else None,
                    )
            self.assertEqual(captured["timeout"], expected)


class BatchTests(unittest.TestCase):
    def test_cached_files_skip_the_queue_and_the_cap(self) -> None:
        entries = [entry("a.exe", sha("a")), entry("b/a.exe", sha("a")), entry("c.dll", sha("c"))]
        cached = {sha("a"): replace(capa_result("old/a.exe"), cached_from={"case_id": CASE})}
        selection = select_capa_entries(entries, max_files=1, cached=cached)
        self.assertEqual([g.representative.relative_path for g in selection.groups], ["c.dll"])
        self.assertEqual(selection.skipped_due_to_limit, 0)
        self.assertEqual(len(selection.cached_groups), 1)

    def test_everything_cached_runs_nothing(self) -> None:
        entries = [entry("a.exe", sha("a")), entry("b/a.exe", sha("a"))]
        cached = {sha("a"): replace(capa_result("old/a.exe"), cached_from={"case_id": CASE})}
        result = run_capa_batch(entries, Path("/nonexistent"), executable="/nonexistent/capa",
                                cached=cached)
        self.assertTrue(result.complete)
        self.assertEqual((result.attempted_files, result.cached_files), (0, 1))
        only = result.results[0]
        self.assertEqual((only.relative_path, only.reused_for), ("a.exe", ("b/a.exe",)))
        self.assertEqual(result.to_dict()["results"][0]["cached_from"]["case_id"], CASE)

        floss_cached = {sha("a"): replace(floss_result("old/a.exe"), cached_from={"case_id": CASE})}
        floss = run_floss_batch(entries, Path("/nonexistent"), executable="/nonexistent/floss",
                                cached=floss_cached)
        self.assertTrue(floss.complete)
        self.assertEqual(floss.cached_files, 1)


class IntegrityTests(unittest.TestCase):
    def test_changed_and_missing_files_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("same.bin", "patched.dll", "gone.exe"):
                (root / name).write_bytes(name.encode())
            entries = [entry(name, hashlib.sha256(name.encode()).hexdigest())
                       for name in ("same.bin", "patched.dll", "gone.exe")]
            (root / "patched.dll").write_bytes(b"patched by something else")
            (root / "gone.exe").unlink()
            result = verify_hashes(entries, root)
        self.assertEqual((result.checked, result.changed, result.unreadable),
                         (2, ("patched.dll",), ("gone.exe",)))
        self.assertFalse(result.ok)
        self.assertEqual(result.to_dict()["changed_count"], 1)


class MountTests(unittest.TestCase):
    def test_cache_is_mounted_read_only(self) -> None:
        request = DockerScanRequest(Path("/src"), Path("/results"), cache_directory=Path("/home/u/cache"))
        command = build_docker_command(request, "/usr/bin/docker", "static-triage-gui-x")
        self.assertIn("type=bind,source=/home/u/cache,target=/cache,readonly", command)


if __name__ == "__main__":
    unittest.main()
