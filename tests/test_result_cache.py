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
        self.assertEqual(added, 2)
        self.assertEqual(result_cache.status(self.cache)["entries"], {"capa": 1, "floss": 1})
        # The same case is never read twice.
        self.assertEqual(result_cache.ingest_case(self.results / CASE, self.cache), 0)

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
        self.assertEqual(result_cache.ingest_results_directory(self.results, self.cache), 2)
        self.assertEqual(result_cache.ingest_results_directory(self.results, self.cache), 0)

    def test_clear_keeps_old_cases_out(self) -> None:
        self.ingest(capa=[capa_result("v1/DoorKickers2.exe")], floss=[])
        self.assertEqual(result_cache.clear(self.cache), 1)
        self.assertEqual(result_cache.ingest_results_directory(self.results, self.cache), 0)
        self.assertEqual(result_cache.status(self.cache)["entries"], {"capa": 0, "floss": 0})


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
