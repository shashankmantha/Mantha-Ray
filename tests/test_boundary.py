from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from static_triage.boundary import (
    resolve_results_root,
    resolve_scan_target,
)
from static_triage.errors import BoundaryError


class BoundaryTests(unittest.TestCase):
    def test_accepts_child_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "staging"
            target = root / "case-input"
            target.mkdir(parents=True)

            resolved_root, resolved_target = (
                resolve_scan_target(
                    root,
                    "case-input",
                )
            )

            self.assertEqual(
                resolved_root,
                root.resolve(),
            )

            self.assertEqual(
                resolved_target,
                target.resolve(),
            )

    def test_rejects_absolute_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "staging"
            root.mkdir()

            with self.assertRaises(BoundaryError):
                resolve_scan_target(
                    root,
                    str(root),
                )

    def test_rejects_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "staging"
            outside = base / "outside"

            root.mkdir()
            outside.mkdir()

            (root / "escape").symlink_to(
                outside,
                target_is_directory=True,
            )

            with self.assertRaises(BoundaryError):
                resolve_scan_target(
                    root,
                    "escape",
                )

    def test_rejects_overlapping_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "staging"
            target = root / "input"
            target.mkdir(parents=True)

            with self.assertRaises(BoundaryError):
                resolve_results_root(
                    root / "results",
                    root.resolve(),
                    target.resolve(),
                )


if __name__ == "__main__":
    unittest.main()