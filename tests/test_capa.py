from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from static_triage.capa import (
    CapaBatchStatus,
    CapaResult,
    CapaStatus,
    parse_capa_capabilities,
    run_capa,
    run_capa_batch,
    select_capa_entries,
)
from static_triage.models import (
    EntryKind,
    EntryState,
    InventoryEntry,
    RoutingClass,
)
from static_triage.runner import CommandResult

def completed_capa_result(
    target: Path,
    scan_root: Path,
    **_: object,
) -> CapaResult:
    """Return a successful mocked per-file result."""

    return CapaResult(
        status=CapaStatus.COMPLETED,
        complete=True,
        relative_path=(
            target.relative_to(scan_root).as_posix()
        ),
        return_code=0,
        capabilities=(),
        timed_out=False,
        output_truncated=False,
        duration_seconds=0.25,
        stdout=example_capa_json(),
        stderr="",
        error=None,
    )


def example_capa_json() -> str:
    """Return a small synthetic capa result document."""

    return json.dumps(
        {
            "meta": {
                "version": "test",
            },
            "rules": {
                "send HTTP request": {
                    "meta": {
                        "name": "send HTTP request",
                        "namespace": "communication/http/client",
                        "lib": False,
                        "att&ck": [
                            {
                                "id": "T1071.001",
                                "parts": [
                                    "Command and Control",
                                    "Application Layer Protocol",
                                    "Web Protocols",
                                ],
                            }
                        ],
                        "mbc": [
                            {
                                "id": "C0002",
                                "parts": [
                                    "Communication",
                                    "HTTP Communication",
                                ],
                            }
                        ],
                    },
                    "source": "synthetic test rule",
                    "matches": [
                        [{"type": "absolute", "value": 4096}, {}],
                        [{"type": "absolute", "value": 8192}, {}],
                    ],
                },
                "internal helper": {
                    "meta": {
                        "name": "internal helper",
                        "namespace": "internal",
                        "lib": True,
                        "att&ck": [],
                        "mbc": [],
                    },
                    "source": "synthetic library rule",
                    "matches": [],
                },
            },
        }
    )


class CapaTests(unittest.TestCase):
    def test_parses_capabilities(self) -> None:
        capabilities = parse_capa_capabilities(
            example_capa_json()
        )

        self.assertEqual(len(capabilities), 1)

        capability = capabilities[0]

        self.assertEqual(
            capability.name,
            "send HTTP request",
        )

        self.assertEqual(
            capability.namespace,
            "communication/http/client",
        )

        self.assertEqual(
            capability.match_count,
            2,
        )

        self.assertEqual(
            capability.attack_ids,
            ("T1071.001",),
        )

        self.assertEqual(
            capability.mbc_ids,
            ("C0002",),
        )

    def test_rejects_invalid_json(self) -> None:
        with self.assertRaises(ValueError):
            parse_capa_capabilities(
                "this is not JSON"
            )

    @patch("static_triage.capa.run_command")
    def test_builds_bounded_json_command(
        self,
        mocked_runner,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scan_root = Path(temporary).resolve()
            sample = scan_root / "sample.exe"
            sample.write_bytes(b"MZ synthetic fixture")

            mocked_runner.return_value = CommandResult(
                command=("capa",),
                return_code=0,
                stdout=example_capa_json(),
                stderr="",
                timed_out=False,
                output_truncated=False,
                duration_seconds=0.25,
            )

            result = run_capa(
                sample,
                scan_root,
                executable="/usr/local/bin/capa",
            )

        command = mocked_runner.call_args.args[0]

        self.assertEqual(
            command,
            [
                "/usr/local/bin/capa",
                "-j",
                "--color",
                "never",
                str(sample),
            ],
        )

        self.assertTrue(result.complete)

        self.assertEqual(
            result.status,
            CapaStatus.COMPLETED,
        )

    @patch("static_triage.capa.run_command")
    def test_normalizes_timeout(
        self,
        mocked_runner,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scan_root = Path(temporary).resolve()
            sample = scan_root / "sample.exe"
            sample.write_bytes(b"MZ synthetic fixture")

            mocked_runner.return_value = CommandResult(
                command=("capa",),
                return_code=-15,
                stdout="",
                stderr="",
                timed_out=True,
                output_truncated=False,
                duration_seconds=300.0,
            )

            result = run_capa(
                sample,
                scan_root,
            )

        self.assertFalse(result.complete)

        self.assertEqual(
            result.status,
            CapaStatus.TIMED_OUT,
        )

        self.assertIn(
            "exceeded its timeout",
            result.error or "",
        )

    @patch("static_triage.capa.run_command")
    def test_truncated_output_is_incomplete(
        self,
        mocked_runner,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scan_root = Path(temporary).resolve()
            sample = scan_root / "sample.exe"
            sample.write_bytes(b"MZ synthetic fixture")

            mocked_runner.return_value = CommandResult(
                command=("capa",),
                return_code=0,
                stdout=example_capa_json(),
                stderr="",
                timed_out=False,
                output_truncated=True,
                duration_seconds=0.5,
            )

            result = run_capa(
                sample,
                scan_root,
            )

        self.assertFalse(result.complete)

        self.assertEqual(
            result.status,
            CapaStatus.ERROR,
        )

        self.assertIn(
            "output exceeded its limit",
            result.error or "",
        )
    def test_selects_only_supported_inventory_entries(
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

        selection = select_capa_entries(
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
                "linux-tool",
                "program.exe",
            ],
        )

        self.assertEqual(
            selection.eligible_count,
            3,
        )

        self.assertEqual(
            selection.skipped_due_to_limit,
            0,
        )

    def test_capa_selection_applies_file_limit(
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

        selection = select_capa_entries(
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

    @patch(
        "static_triage.capa.run_capa",
        side_effect=completed_capa_result,
    )
    def test_batch_runs_only_selected_binaries(
        self,
        mocked_capa,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scan_root = Path(temporary).resolve()

            entries = [
                InventoryEntry(
                    relative_path="a.exe",
                    kind=EntryKind.REGULAR_FILE,
                    state=EntryState.INVENTORIED,
                    routing_class=(
                        RoutingClass.PE_EXECUTABLE
                    ),
                ),
                InventoryEntry(
                    relative_path="b.dll",
                    kind=EntryKind.REGULAR_FILE,
                    state=EntryState.INVENTORIED,
                    routing_class=RoutingClass.PE_DLL,
                ),
                InventoryEntry(
                    relative_path="notes.txt",
                    kind=EntryKind.REGULAR_FILE,
                    state=EntryState.INVENTORIED,
                    routing_class=RoutingClass.TEXT,
                ),
            ]

            result = run_capa_batch(
                entries,
                scan_root,
                max_files=10,
                file_timeout_seconds=30,
                total_timeout_seconds=120,
                max_output_bytes=1000,
            )

        self.assertTrue(result.complete)

        self.assertEqual(
            result.status,
            CapaBatchStatus.COMPLETED,
        )

        self.assertEqual(result.eligible_files, 2)
        self.assertEqual(result.attempted_files, 2)
        self.assertEqual(mocked_capa.call_count, 2)

    @patch(
        "static_triage.capa.run_capa",
        side_effect=completed_capa_result,
    )
    def test_batch_records_file_limit(
        self,
        mocked_capa,
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
                    "a.exe",
                    "b.exe",
                    "c.exe",
                )
            ]

            result = run_capa_batch(
                entries,
                scan_root,
                max_files=2,
                file_timeout_seconds=30,
                total_timeout_seconds=120,
                max_output_bytes=1000,
            )

        self.assertFalse(result.complete)

        self.assertEqual(
            result.status,
            CapaBatchStatus.PARTIAL,
        )

        self.assertEqual(
            result.skipped_due_to_limit,
            1,
        )

        self.assertEqual(mocked_capa.call_count, 2)

    @patch(
        "static_triage.capa.time.monotonic",
        side_effect=[
            0.0,
            0.0,
            11.0,
            11.0,
        ],
    )
    @patch(
        "static_triage.capa.run_capa",
        side_effect=completed_capa_result,
    )
    def test_batch_enforces_total_timeout(
        self,
        mocked_capa,
        _mocked_monotonic,
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
                    "a.exe",
                    "b.exe",
                )
            ]

            result = run_capa_batch(
                entries,
                scan_root,
                max_files=10,
                file_timeout_seconds=5,
                total_timeout_seconds=10,
                max_output_bytes=1000,
            )

        self.assertFalse(result.complete)

        self.assertEqual(
            result.skipped_due_to_timeout,
            1,
        )

        self.assertEqual(mocked_capa.call_count, 1)

    @patch("static_triage.capa.run_command")
    def test_uses_configured_capa_resources(
        self,
        mocked_runner,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scan_root = Path(temporary).resolve()
            sample = scan_root / "sample.exe"
            rules = scan_root / "rules"
            signatures = scan_root / "signatures"

            sample.write_bytes(
                b"MZ synthetic fixture"
            )

            rules.mkdir()
            signatures.mkdir()

            mocked_runner.return_value = CommandResult(
                command=("capa",),
                return_code=0,
                stdout=example_capa_json(),
                stderr="",
                timed_out=False,
                output_truncated=False,
                duration_seconds=0.25,
            )

            with patch.dict(
                "os.environ",
                {
                    "CAPA_RULES_PATH": str(rules),
                    "CAPA_SIGNATURES_PATH": (
                        str(signatures)
                    ),
                },
                clear=False,
            ):
                result = run_capa(
                    sample,
                    scan_root,
                    executable="/usr/local/bin/capa",
                )

        mocked_runner.assert_called_once()

        command = mocked_runner.call_args.args[0]

        self.assertEqual(
            command,
            [
                "/usr/local/bin/capa",
                "-r",
                str(rules),
                "-s",
                str(signatures),
                "-j",
                "--color",
                "never",
                str(sample),
            ],
        )

        environment = (
            mocked_runner.call_args.kwargs["env"]
        )

        self.assertEqual(
            environment["HOME"],
            "/tmp/capa-home",
        )

        self.assertEqual(
            environment["USER"],
            "static-triage",
        )

        self.assertTrue(result.complete)

if __name__ == "__main__":
    unittest.main()