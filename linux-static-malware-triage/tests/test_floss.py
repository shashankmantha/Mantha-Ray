from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from static_triage.floss import (
    FlossBatchStatus,
    FlossResult,
    FlossStatus,
    FlossString,
    parse_floss_strings,
    run_floss,
    run_floss_batch,
    select_floss_entries,
)

from static_triage.models import (
    EntryKind,
    EntryState,
    InventoryEntry,
    RoutingClass,
)

from static_triage.runner import CommandResult


def example_floss_json() -> str:
    """Return a small synthetic FLOSS result document."""

    return json.dumps(
        {
            "metadata": {
                "file_path": "sample.exe",
            },
            "strings": {
                "decoded_strings": [
                    {
                        "string": "decoded command",
                        "encoding": "ASCII",
                    }
                ],
                "tight_strings": [
                    {
                        "string": "tight-loop string",
                        "encoding": "ASCII",
                    }
                ],
                "stack_strings": [
                    {
                        "string": "stack-built string",
                        "encoding": "UTF-16LE",
                    }
                ],
                "language_strings": [],
                "language_strings_missed": [],
                "static_strings": [
                    {
                        "string": "ordinary static string",
                        "encoding": "ASCII",
                    }
                ],
            },
        }
    )

def completed_floss_result(
    relative_path: str,
) -> FlossResult:
    """Create a completed synthetic FLOSS result."""

    return FlossResult(
        status=FlossStatus.COMPLETED,
        complete=True,
        relative_path=relative_path,
        return_code=0,
        strings=(
            FlossString(
                kind="decoded",
                value="synthetic decoded string",
                encoding="ASCII",
                truncated=False,
            ),
        ),
        total_strings=1,
        strings_truncated=False,
        timed_out=False,
        output_truncated=False,
        duration_seconds=0.25,
        stdout=example_floss_json(),
        stderr="",
        error=None,
    )

class FlossTests(unittest.TestCase):
    def test_parses_normalized_strings(self) -> None:
        strings, total, truncated = parse_floss_strings(
            example_floss_json()
        )

        self.assertEqual(total, 4)
        self.assertFalse(truncated)

        self.assertEqual(
            [item.kind for item in strings],
            [
                "decoded",
                "tight",
                "stack",
                "static",
            ],
        )

        self.assertEqual(
            strings[0].value,
            "decoded command",
        )

        self.assertEqual(
            strings[2].encoding,
            "UTF-16LE",
        )

    def test_applies_total_string_limit(self) -> None:
        strings, total, truncated = parse_floss_strings(
            example_floss_json(),
            max_strings=2,
        )

        self.assertEqual(total, 4)
        self.assertEqual(len(strings), 2)
        self.assertTrue(truncated)

        # Higher-value deobfuscated strings are retained first.
        self.assertEqual(
            [item.kind for item in strings],
            [
                "decoded",
                "tight",
            ],
        )

    def test_truncates_individual_long_strings(self) -> None:
        payload = json.dumps(
            {
                "strings": {
                    "decoded_strings": [
                        {
                            "string": "A" * 100,
                            "encoding": "ASCII",
                        }
                    ],
                    "tight_strings": [],
                    "stack_strings": [],
                    "language_strings": [],
                    "language_strings_missed": [],
                    "static_strings": [],
                }
            }
        )

        strings, total, collection_truncated = (
            parse_floss_strings(
                payload,
                max_string_chars=16,
            )
        )

        self.assertEqual(total, 1)
        self.assertTrue(collection_truncated)
        self.assertEqual(len(strings), 1)
        self.assertTrue(strings[0].truncated)
        self.assertLessEqual(
            len(strings[0].value),
            16,
        )
        self.assertTrue(
            strings[0].value.endswith("…")
        )

    def test_rejects_invalid_json(self) -> None:
        with self.assertRaises(ValueError):
            parse_floss_strings(
                "this is not JSON"
            )

    @patch("static_triage.floss.run_command")
    def test_builds_bounded_json_command(
        self,
        mocked_runner,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scan_root = Path(temporary).resolve()
            sample = scan_root / "sample.exe"
            sample.write_bytes(
                b"MZ synthetic fixture"
            )

            mocked_runner.return_value = CommandResult(
                command=("floss",),
                return_code=0,
                stdout=example_floss_json(),
                stderr="",
                timed_out=False,
                output_truncated=False,
                duration_seconds=0.25,
            )

            result = run_floss(
                sample,
                scan_root,
                executable="/usr/local/bin/floss",
            )

        mocked_runner.assert_called_once()

        command = mocked_runner.call_args.args[0]

        self.assertEqual(
            command,
            [
                "/usr/local/bin/floss",
                "-j",
                "--no",
                "static",
                "--",
                str(sample),
            ],
        )

        self.assertTrue(result.complete)
        self.assertEqual(
            result.status,
            FlossStatus.COMPLETED,
        )
        self.assertEqual(
            result.total_strings,
            4,
        )

    @patch("static_triage.floss.run_command")
    def test_normalizes_timeout(
        self,
        mocked_runner,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scan_root = Path(temporary).resolve()
            sample = scan_root / "sample.exe"
            sample.write_bytes(
                b"MZ synthetic fixture"
            )

            mocked_runner.return_value = CommandResult(
                command=("floss",),
                return_code=-15,
                stdout="",
                stderr="",
                timed_out=True,
                output_truncated=False,
                duration_seconds=600.0,
            )

            result = run_floss(
                sample,
                scan_root,
            )

        self.assertFalse(result.complete)
        self.assertEqual(
            result.status,
            FlossStatus.TIMED_OUT,
        )
        self.assertIn(
            "exceeded its timeout",
            result.error or "",
        )

    @patch("static_triage.floss.run_command")
    def test_truncated_output_is_incomplete(
        self,
        mocked_runner,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scan_root = Path(temporary).resolve()
            sample = scan_root / "sample.exe"
            sample.write_bytes(
                b"MZ synthetic fixture"
            )

            mocked_runner.return_value = CommandResult(
                command=("floss",),
                return_code=0,
                stdout=example_floss_json(),
                stderr="",
                timed_out=False,
                output_truncated=True,
                duration_seconds=0.5,
            )

            result = run_floss(
                sample,
                scan_root,
            )

        self.assertFalse(result.complete)
        self.assertEqual(
            result.status,
            FlossStatus.ERROR,
        )
        self.assertIn(
            "output exceeded its byte limit",
            result.error or "",
        )


    def test_selects_only_inventoried_pe_files(
        self,
    ) -> None:
        entries = [
            InventoryEntry(
                relative_path="program.exe",
                kind=EntryKind.REGULAR_FILE,
                state=EntryState.INVENTORIED,
                routing_class=RoutingClass.PE_EXECUTABLE,
            ),
            InventoryEntry(
                relative_path="library.dll",
                kind=EntryKind.REGULAR_FILE,
                state=EntryState.INVENTORIED,
                routing_class=RoutingClass.PE_DLL,
            ),
            InventoryEntry(
                relative_path="linux-tool",
                kind=EntryKind.REGULAR_FILE,
                state=EntryState.INVENTORIED,
                routing_class=RoutingClass.ELF,
            ),
            InventoryEntry(
                relative_path="notes.txt",
                kind=EntryKind.REGULAR_FILE,
                state=EntryState.INVENTORIED,
                routing_class=RoutingClass.TEXT,
            ),
            InventoryEntry(
                relative_path="linked.exe",
                kind=EntryKind.SYMLINK,
                state=EntryState.SKIPPED,
                routing_class=RoutingClass.PE_EXECUTABLE,
            ),
        ]

        selection = select_floss_entries(
            entries,
            max_files=10,
        )

        self.assertEqual(
            [
                entry.relative_path
                for entry in selection.entries
            ],
            [
                "library.dll",
                "program.exe",
            ],
        )

        self.assertEqual(
            selection.eligible_count,
            2,
        )

        self.assertEqual(
            selection.skipped_due_to_limit,
            0,
        )

    def test_floss_selection_applies_file_limit(
        self,
    ) -> None:
        entries = [
            InventoryEntry(
                relative_path=name,
                kind=EntryKind.REGULAR_FILE,
                state=EntryState.INVENTORIED,
                routing_class=RoutingClass.PE_EXECUTABLE,
            )
            for name in (
                "z.exe",
                "a.exe",
                "m.exe",
            )
        ]

        selection = select_floss_entries(
            entries,
            max_files=2,
        )

        self.assertEqual(
            [
                entry.relative_path
                for entry in selection.entries
            ],
            [
                "a.exe",
                "m.exe",
            ],
        )

        self.assertEqual(
            selection.eligible_count,
            3,
        )

        self.assertEqual(
            selection.skipped_due_to_limit,
            1,
        )

    @patch("static_triage.floss.run_floss")
    def test_batch_runs_only_selected_pe_files(
        self,
        mocked_floss,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scan_root = Path(temporary).resolve()

            entries = [
                InventoryEntry(
                    relative_path="program.exe",
                    kind=EntryKind.REGULAR_FILE,
                    state=EntryState.INVENTORIED,
                    routing_class=(
                        RoutingClass.PE_EXECUTABLE
                    ),
                ),
                InventoryEntry(
                    relative_path="library.dll",
                    kind=EntryKind.REGULAR_FILE,
                    state=EntryState.INVENTORIED,
                    routing_class=RoutingClass.PE_DLL,
                ),
                InventoryEntry(
                    relative_path="linux-tool",
                    kind=EntryKind.REGULAR_FILE,
                    state=EntryState.INVENTORIED,
                    routing_class=RoutingClass.ELF,
                ),
                InventoryEntry(
                    relative_path="notes.txt",
                    kind=EntryKind.REGULAR_FILE,
                    state=EntryState.INVENTORIED,
                    routing_class=RoutingClass.TEXT,
                ),
            ]

            def fake_floss(
                target,
                supplied_root,
                **kwargs,
            ):
                return completed_floss_result(
                    target.relative_to(
                        supplied_root
                    ).as_posix()
                )

            mocked_floss.side_effect = fake_floss

            result = run_floss_batch(
                entries,
                scan_root,
                max_files=10,
            )

        self.assertTrue(result.complete)
        self.assertEqual(
            result.status,
            FlossBatchStatus.COMPLETED,
        )
        self.assertEqual(result.eligible_files, 2)
        self.assertEqual(result.attempted_files, 2)
        self.assertEqual(mocked_floss.call_count, 2)

        self.assertEqual(
            [
                item.relative_path
                for item in result.results
            ],
            [
                "library.dll",
                "program.exe",
            ],
        )

        self.assertEqual(
            result.to_dict()[
                "extracted_string_count"
            ],
            2,
        )

    @patch("static_triage.floss.run_floss")
    def test_batch_records_file_limit(
        self,
        mocked_floss,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scan_root = Path(temporary).resolve()

            entries = [
                InventoryEntry(
                    relative_path=name,
                    kind=EntryKind.REGULAR_FILE,
                    state=EntryState.INVENTORIED,
                    routing_class=(
                        RoutingClass.PE_EXECUTABLE
                    ),
                )
                for name in (
                    "z.exe",
                    "a.exe",
                    "m.exe",
                )
            ]

            def fake_floss(
                target,
                supplied_root,
                **kwargs,
            ):
                return completed_floss_result(
                    target.relative_to(
                        supplied_root
                    ).as_posix()
                )

            mocked_floss.side_effect = fake_floss

            result = run_floss_batch(
                entries,
                scan_root,
                max_files=2,
            )

        self.assertFalse(result.complete)
        self.assertEqual(
            result.status,
            FlossBatchStatus.PARTIAL,
        )
        self.assertEqual(result.eligible_files, 3)
        self.assertEqual(result.attempted_files, 2)
        self.assertEqual(
            result.skipped_due_to_limit,
            1,
        )
        self.assertEqual(mocked_floss.call_count, 2)
        self.assertIn(
            "file-count limit",
            result.error or "",
        )

    @patch("static_triage.floss.run_floss")
    def test_batch_enforces_total_timeout(
        self,
        mocked_floss,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scan_root = Path(temporary).resolve()

            entries = [
                InventoryEntry(
                    relative_path=name,
                    kind=EntryKind.REGULAR_FILE,
                    state=EntryState.INVENTORIED,
                    routing_class=(
                        RoutingClass.PE_EXECUTABLE
                    ),
                )
                for name in (
                    "one.exe",
                    "two.exe",
                )
            ]

            def fake_floss(
                target,
                supplied_root,
                **kwargs,
            ):
                return completed_floss_result(
                    target.relative_to(
                        supplied_root
                    ).as_posix()
                )

            mocked_floss.side_effect = fake_floss

            with patch(
                "static_triage.floss.time.monotonic",
                side_effect=[
                    0.0,
                    0.0,
                    11.0,
                    11.0,
                ],
            ):
                result = run_floss_batch(
                    entries,
                    scan_root,
                    total_timeout_seconds=10.0,
                )

        self.assertFalse(result.complete)
        self.assertEqual(
            result.status,
            FlossBatchStatus.PARTIAL,
        )
        self.assertEqual(result.attempted_files, 1)
        self.assertEqual(
            result.skipped_due_to_timeout,
            1,
        )
        self.assertEqual(mocked_floss.call_count, 1)
        self.assertIn(
            "total-time limit",
            result.error or "",
        )


if __name__ == "__main__":
    unittest.main()