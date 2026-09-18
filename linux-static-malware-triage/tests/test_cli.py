from __future__ import annotations

import unittest

from static_triage.cli import build_parser


class CliTests(unittest.TestCase):
    def test_gui_uses_safe_defaults(self) -> None:
        args = build_parser().parse_args(["gui"])

        self.assertEqual(args.command, "gui")
        self.assertEqual(args.container_engine, "docker")
        self.assertEqual(args.image, "static-triage:core")

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
        self.assertEqual(args.staging_subdirectory, "sample")
        self.assertEqual(args.max_files, 25_000)


if __name__ == "__main__":
    unittest.main()
