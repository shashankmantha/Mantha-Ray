from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from static_triage.config import ScanLimits
from static_triage.inventory import inventory_tree
from static_triage.models import (
    EntryKind,
    EntryState,
    RoutingClass,
)


def minimal_pe(*, dll: bool = False) -> bytes:
    """Create a safe synthetic PE header for routing tests."""

    data = bytearray(256)

    data[0:2] = b"MZ"
    data[0x3C:0x40] = (128).to_bytes(
        4,
        "little",
    )

    data[128:132] = b"PE\x00\x00"

    characteristics = (
        0x2000
        if dll
        else 0x0002
    )

    data[150:152] = characteristics.to_bytes(
        2,
        "little",
    )

    return bytes(data)


class InventoryTests(unittest.TestCase):
    def test_hashes_and_routes_by_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = minimal_pe()

            sample = root / "totally-safe.txt"
            sample.write_bytes(payload)

            entries, summary = inventory_tree(
                root,
                ScanLimits(),
            )

            entry = entries[0]

            self.assertEqual(
                entry.sha256,
                hashlib.sha256(payload).hexdigest(),
            )

            self.assertEqual(
                entry.routing_class,
                RoutingClass.PE_EXECUTABLE,
            )

            self.assertTrue(
                any(
                    "extension/type mismatch" in item
                    for item in entry.evidence
                )
            )

            self.assertEqual(
                summary.hashed_files,
                1,
            )

            self.assertEqual(
                summary.supported_binaries,
                1,
            )

    def test_normal_text_has_no_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            (root / "config.txt").write_text(
                "normal text fixture\n",
                encoding="utf-8",
            )

            entries, summary = inventory_tree(
                root,
                ScanLimits(),
            )

            self.assertEqual(
                entries[0].routing_class,
                RoutingClass.TEXT,
            )

            self.assertEqual(
                entries[0].evidence,
                [],
            )

            self.assertEqual(
                summary.review_flags,
                0,
            )

    def test_flags_double_extension(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            (root / "invoice.pdf.exe").write_bytes(
                minimal_pe()
            )

            entries, _ = inventory_tree(
                root,
                ScanLimits(),
            )

            self.assertIn(
                "double-extension filename",
                entries[0].evidence,
            )

    def test_records_symlink_without_following_it(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "input"
            root.mkdir()

            secret = base / "secret.txt"
            secret.write_text(
                "do not hash me",
                encoding="utf-8",
            )

            (root / "outside-link").symlink_to(secret)

            entries, summary = inventory_tree(
                root,
                ScanLimits(),
            )

            self.assertEqual(
                len(entries),
                1,
            )

            self.assertEqual(
                entries[0].kind,
                EntryKind.SYMLINK,
            )

            self.assertEqual(
                entries[0].state,
                EntryState.SKIPPED,
            )

            self.assertIsNone(
                entries[0].sha256
            )

            self.assertEqual(
                summary.skipped_entries,
                1,
            )

    def test_records_fifo_without_opening_it(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fifo = root / "do-not-block"

            os.mkfifo(fifo)

            entries, summary = inventory_tree(
                root,
                ScanLimits(),
            )

            self.assertEqual(
                entries[0].kind,
                EntryKind.FIFO,
            )

            self.assertEqual(
                entries[0].state,
                EntryState.SKIPPED,
            )

            self.assertEqual(
                summary.skipped_entries,
                1,
            )

    def test_file_count_limit_returns_partial_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            (root / "one.txt").write_text(
                "one",
                encoding="utf-8",
            )

            (root / "two.txt").write_text(
                "two",
                encoding="utf-8",
            )

            entries, summary = inventory_tree(
                root,
                ScanLimits(max_file_count=1),
            )

            self.assertEqual(
                summary.limit_exceeded,
                1,
            )

            self.assertEqual(
                len(entries),
                2,
            )

            self.assertTrue(
                any(
                    entry.state
                    == EntryState.LIMIT_EXCEEDED
                    for entry in entries
                )
            )


if __name__ == "__main__":
    unittest.main()