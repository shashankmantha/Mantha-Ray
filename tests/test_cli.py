from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout

from static_triage.cli import (
    _print_progress,
    build_parser,
)


class CliTests(unittest.TestCase):
    def test_gui_uses_safe_defaults(self) -> None:
        args = build_parser().parse_args(["gui"])

        self.assertEqual(args.command, "gui")
        self.assertEqual(
            args.container_engine,
            "docker",
        )
        self.assertEqual(
            args.image,
            "static-triage:core",
        )

    def test_scan_contract_is_unchanged(self) -> None:
        args = build_parser().parse_args(
            [
                "scan",
                "sample",
                "--staging-root",
                "/staging",
                "--results-root",
                "/results",
            ]
        )

        self.assertEqual(args.command, "scan")
        self.assertEqual(
            args.staging_subdirectory,
            "sample",
        )
        self.assertEqual(args.max_files, 25_000)
        self.assertFalse(args.progress_jsonl)

    def test_scan_accepts_internal_progress_protocol(
        self,
    ) -> None:
        args = build_parser().parse_args(
            [
                "scan",
                "sample",
                "--staging-root",
                "/staging",
                "--results-root",
                "/results",
                "--progress-jsonl",
            ]
        )

        self.assertTrue(args.progress_jsonl)

    def test_progress_event_is_flushed_jsonl(self) -> None:
        output = io.StringIO()

        with redirect_stdout(output):
            _print_progress(
                "capa",
                "running",
                "capa is analyzing eligible binaries...",
            )

        lines = output.getvalue().splitlines()

        self.assertEqual(len(lines), 1)

        payload = json.loads(lines[0])

        self.assertEqual(
            payload,
            {
                "message": (
                    "capa is analyzing "
                    "eligible binaries..."
                ),
                "stage": "capa",
                "status": "running",
                "type": "progress",
            },
        )


if __name__ == "__main__":
    unittest.main()