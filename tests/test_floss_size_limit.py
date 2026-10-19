from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from static_triage.capa import select_capa_entries
from static_triage.config import ScanConfig
from static_triage.floss import (
    FLOSS_MAX_FILE_BYTES,
    FlossBatchStatus,
    FlossResult,
    FlossStatus,
    _normalize_result,
    run_floss_batch,
    select_floss_entries,
)
from static_triage.models import (
    EntryKind,
    EntryState,
    InventoryEntry,
    RoutingClass,
    ToolInfo,
)
from static_triage.runner import CommandResult
from static_triage.scanner import run_inventory_scan


def minimal_pe_dll() -> bytes:
    """A safe synthetic PE DLL header (same layout as test_inventory)."""

    data = bytearray(256)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (128).to_bytes(4, "little")
    data[128:132] = b"PE\x00\x00"
    data[150:152] = (0x2000).to_bytes(2, "little")
    return bytes(data)

LIMIT = FLOSS_MAX_FILE_BYTES


def pe(path, size, digest=None):
    return InventoryEntry(
        relative_path=path,
        kind=EntryKind.REGULAR_FILE,
        state=EntryState.INVENTORIED,
        sha256=digest or (path.encode().hex() * 64)[:64],
        size_bytes=size,
        routing_class=RoutingClass.PE_EXECUTABLE,
    )


def completed(target, scan_root, **_):
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
        duration_seconds=1.0,
        stdout="{}",
        stderr="",
    )


class SelectionTests(unittest.TestCase):
    def test_limit_matches_floss(self) -> None:
        self.assertEqual(LIMIT, 16 * 1024 * 1024)

    def test_oversized_files_are_set_aside(self) -> None:
        selection = select_floss_entries(
            [
                pe("avcodec-59.dll", 51_487_232),
                pe("avfilter-8.dll", 19_397_632),
                pe("steam_api64.dll", 300_000),
            ],
            max_files=50,
        )
        self.assertEqual(
            [e.relative_path for e in selection.entries],
            ["steam_api64.dll"],
        )
        self.assertEqual(
            selection.oversized_paths,
            ("avcodec-59.dll", "avfilter-8.dll"),
        )
        self.assertEqual(selection.eligible_count, 3)
        self.assertEqual(selection.skipped_due_to_limit, 0)

    def test_boundary_matches_floss(self) -> None:
        # FLOSS refuses only files strictly larger than the limit.
        selection = select_floss_entries(
            [pe("exact.dll", LIMIT), pe("over.dll", LIMIT + 1)],
            max_files=50,
        )
        self.assertEqual(
            [e.relative_path for e in selection.entries],
            ["exact.dll"],
        )
        self.assertEqual(selection.oversized_paths, ("over.dll",))

    def test_unknown_size_is_attempted(self) -> None:
        selection = select_floss_entries(
            [pe("unknown.dll", None), pe("flag.dll", True)],
            max_files=50,
        )
        self.assertEqual(len(selection.entries), 2)
        self.assertEqual(selection.oversized_paths, ())

    def test_capa_still_analyzes_oversized_files(self) -> None:
        selection = select_capa_entries(
            [pe("avcodec-59.dll", 51_487_232)],
            max_files=50,
        )
        self.assertEqual(len(selection.entries), 1)


class BatchTests(unittest.TestCase):
    def test_oversized_never_launched_and_stage_completes(self) -> None:
        same = "e" * 64
        entries = [
            pe("avcodec-59.dll", 51_487_232, same),
            pe("v1.10/avcodec-59.dll", 51_487_232, same),
            pe("steam_api64.dll", 300_000),
        ]
        with (
            patch("static_triage.floss.run_floss", side_effect=completed) as run,
            tempfile.TemporaryDirectory() as temporary,
        ):
            result = run_floss_batch(entries, Path(temporary))
        self.assertEqual(run.call_count, 1)
        self.assertTrue(result.complete)
        self.assertEqual(result.status, FlossBatchStatus.COMPLETED)
        self.assertIsNone(result.error)
        self.assertEqual(
            result.skipped_size_paths,
            ("avcodec-59.dll", "v1.10/avcodec-59.dll"),
        )
        payload = result.to_dict()
        self.assertEqual(payload["skipped_due_to_size"], 2)
        self.assertEqual(payload["size_limit_bytes"], LIMIT)
        self.assertEqual(payload["eligible_files"], 3)
        self.assertEqual(payload["attempted_files"], 1)

    def test_only_oversized_files(self) -> None:
        with (
            patch("static_triage.floss.run_floss") as run,
            tempfile.TemporaryDirectory() as temporary,
        ):
            result = run_floss_batch(
                [pe("huge.dll", LIMIT * 3)],
                Path(temporary),
            )
        run.assert_not_called()
        self.assertTrue(result.complete)
        self.assertEqual(result.skipped_due_to_size, 1)

    def test_refusal_message_if_floss_still_rejects(self) -> None:
        execution = CommandResult(
            command=("floss",),
            return_code=255,
            stdout="",
            stderr=(
                "ERROR: floss: cannot deobfuscate strings from "
                "files larger than 0x1000000 bytes\n"
            ),
            timed_out=False,
            output_truncated=False,
            duration_seconds=3.0,
        )
        result = _normalize_result(
            execution,
            "big.dll",
            max_strings=10,
            max_string_chars=100,
        )
        self.assertEqual(result.status, FlossStatus.ERROR)
        self.assertIn("16 MiB", result.error)

    def test_other_failures_keep_generic_message(self) -> None:
        execution = CommandResult(
            command=("floss",),
            return_code=255,
            stdout="",
            stderr="something else\n",
            timed_out=False,
            output_truncated=False,
            duration_seconds=3.0,
        )
        result = _normalize_result(
            execution, "x.dll", max_strings=10, max_string_chars=100
        )
        self.assertIn("unexpected code 255", result.error)


class ReportTests(unittest.TestCase):
    def test_oversized_file_is_not_a_coverage_gap(self) -> None:
        tools = [ToolInfo(name="floss", executable="/usr/bin/floss", available=True)]
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            sample = base / "staging" / "sample"
            sample.mkdir(parents=True)
            big = sample / "avcodec-59.dll"
            with big.open("wb") as handle:
                handle.write(minimal_pe_dll())
                handle.truncate(LIMIT + 4096)
            with (
                patch("static_triage.scanner.inspect_tools", return_value=tools),
                patch("static_triage.floss.run_floss") as run,
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

        floss = report["analyzers"]["floss"]
        self.assertEqual(floss["eligible_files"], 1)
        run.assert_not_called()
        self.assertTrue(floss["complete"])
        self.assertEqual(floss["skipped_size_paths"], ["avcodec-59.dll"])
        self.assertNotIn(
            "FLOSS analysis was incomplete",
            " ".join(report["incomplete_reasons"]),
        )
        self.assertIn("over FLOSS's 16 MiB limit", markdown)


if __name__ == "__main__":
    unittest.main()