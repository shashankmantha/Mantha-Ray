from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from static_triage.capa import select_capa_entries
from static_triage.config import ScanConfig
from static_triage.floss import (
    FLOSS_EMULATION_MAX_BYTES,
    FLOSS_MAX_FILE_BYTES,
    FlossBatchStatus,
    FlossResult,
    FlossStatus,
    _normalize_result,
    run_floss_batch,
    select_floss_entries,
    wants_plain_strings,
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


EMULATION_LIMIT = FLOSS_EMULATION_MAX_BYTES


class SelectionTests(unittest.TestCase):
    def test_limit_matches_floss(self) -> None:
        self.assertEqual(LIMIT, 16 * 1024 * 1024)
        self.assertEqual(EMULATION_LIMIT, 4 * 1024 * 1024)

    def test_big_files_get_plain_strings_first(self) -> None:
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
            ["avfilter-8.dll", "avcodec-59.dll", "steam_api64.dll"],
        )
        self.assertTrue(wants_plain_strings(selection.entries[0]))
        self.assertFalse(wants_plain_strings(selection.entries[2]))
        self.assertEqual(selection.oversized_paths, ())
        self.assertEqual(selection.eligible_count, 3)
        self.assertEqual(selection.skipped_due_to_limit, 0)

    def test_emulation_boundary(self) -> None:
        self.assertFalse(wants_plain_strings(pe("exact.dll", EMULATION_LIMIT)))
        self.assertTrue(wants_plain_strings(pe("over.dll", EMULATION_LIMIT + 1)))

    def test_plain_files_do_not_use_the_file_cap(self) -> None:
        selection = select_floss_entries(
            [pe(f"big{i}.dll", 10_000_000 + i) for i in range(3)]
            + [pe("a.dll", 10), pe("b.dll", 20)],
            max_files=1,
        )
        self.assertEqual(len(selection.entries), 4)
        self.assertEqual(selection.skipped_due_to_limit, 1)

    def test_unknown_size_is_emulated(self) -> None:
        for entry in (pe("unknown.dll", None), pe("flag.dll", True)):
            with self.subTest(path=entry.relative_path):
                self.assertFalse(wants_plain_strings(entry))

    def test_capa_still_analyzes_big_files(self) -> None:
        selection = select_capa_entries(
            [pe("avcodec-59.dll", 51_487_232)],
            max_files=50,
        )
        self.assertEqual(len(selection.entries), 1)


def plain_done(target, scan_root):
    return FlossResult(
        status=FlossStatus.COMPLETED,
        complete=True,
        relative_path=target.relative_to(scan_root).as_posix(),
        return_code=0,
        strings=(),
        total_strings=12,
        strings_truncated=False,
        timed_out=False,
        output_truncated=False,
        duration_seconds=0.5,
        stdout="",
        stderr="",
        mode="plain",
        fully_scanned=True,
    )


class BatchTests(unittest.TestCase):
    def test_big_files_never_emulated_and_stage_completes(self) -> None:
        same = "e" * 64
        entries = [
            pe("avcodec-59.dll", 51_487_232, same),
            pe("v1.10/avcodec-59.dll", 51_487_232, same),
            pe("DoorKickers2.exe", 8_557_056),
            pe("steam_api64.dll", 300_000),
        ]
        with (
            patch("static_triage.floss.run_floss", side_effect=completed) as run,
            patch(
                "static_triage.floss.run_plain_strings", side_effect=plain_done
            ) as plain,
            tempfile.TemporaryDirectory() as temporary,
        ):
            result = run_floss_batch(entries, Path(temporary))
        self.assertEqual(run.call_count, 1)
        self.assertEqual(plain.call_count, 2)
        self.assertTrue(result.complete)
        self.assertEqual(result.status, FlossBatchStatus.COMPLETED)
        self.assertIsNone(result.error)
        payload = result.to_dict()
        self.assertEqual(payload["plain_strings_files"], 2)
        self.assertEqual(payload["skipped_due_to_size"], 0)
        self.assertEqual(payload["emulation_max_bytes"], EMULATION_LIMIT)
        self.assertEqual(payload["eligible_files"], 4)
        self.assertEqual(payload["attempted_files"], 3)
        modes = {r["relative_path"]: r["mode"] for r in payload["results"]}
        self.assertEqual(modes["avcodec-59.dll"], "plain")
        self.assertEqual(modes["steam_api64.dll"], "emulation")

    def test_plain_progress_messages(self) -> None:
        messages: list[str] = []
        with (
            patch("static_triage.floss.run_plain_strings", side_effect=plain_done),
            tempfile.TemporaryDirectory() as temporary,
        ):
            run_floss_batch(
                [pe("huge.dll", LIMIT * 3)],
                Path(temporary),
                on_file=messages.append,
            )
        self.assertEqual(
            messages[0], "FLOSS 1/1 started (plain strings): huge.dll (48.0 MB)"
        )

    def test_missing_file_is_an_error_not_a_crash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = run_floss_batch([pe("gone.dll", LIMIT * 3)], Path(temporary))
        self.assertFalse(result.complete)
        self.assertEqual(result.results[0].mode, "plain")
        self.assertIn("plain-strings pass failed", result.results[0].error)

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
    def test_file_over_16_mib_gets_plain_strings(self) -> None:
        tools = [ToolInfo(name="floss", executable="/usr/bin/floss", available=True)]
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            sample = base / "staging" / "sample"
            sample.mkdir(parents=True)
            big = sample / "avcodec-59.dll"
            with big.open("wb") as handle:
                handle.write(minimal_pe_dll())
                handle.write(b"\0" * 512)
                handle.write(b"stratum+tcp://pool.example.invalid:3333\0")
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
        run.assert_not_called()
        self.assertTrue(floss["complete"])
        self.assertEqual(floss["skipped_size_paths"], [])
        item = floss["results"][0]
        self.assertEqual(item["mode"], "plain")
        self.assertTrue(item["fully_scanned"])
        self.assertEqual(item["strings"][0]["category"], "miner pool")
        self.assertNotIn(
            "FLOSS analysis was incomplete",
            " ".join(report["incomplete_reasons"]),
        )
        self.assertIn("Plain strings only (over 4 MiB, no emulation): `1`", markdown)


if __name__ == "__main__":
    unittest.main()