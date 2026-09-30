from __future__ import annotations

import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

from static_triage.capa import (
    CapaBatchStatus,
    CapaCapability,
    CapaResult,
    CapaStatus,
    run_capa_batch,
    select_capa_entries,
)
from static_triage.floss import (
    FlossBatchStatus,
    FlossResult,
    FlossStatus,
    FlossString,
    run_floss_batch,
)
from static_triage.models import (
    EntryKind,
    EntryState,
    InventoryEntry,
    RoutingClass,
)


def binary_entry(
    path: str,
    digest: str | None,
    *,
    routing_class: RoutingClass = (
        RoutingClass.PE_EXECUTABLE
    ),
) -> InventoryEntry:
    return InventoryEntry(
        relative_path=path,
        kind=EntryKind.REGULAR_FILE,
        state=EntryState.INVENTORIED,
        sha256=digest,
        routing_class=routing_class,
    )


def completed_capa_result(
    target: Path,
    scan_root: Path,
    **_: object,
) -> CapaResult:
    return CapaResult(
        status=CapaStatus.COMPLETED,
        complete=True,
        relative_path=(
            target.relative_to(scan_root).as_posix()
        ),
        return_code=0,
        capabilities=(
            CapaCapability(
                name="synthetic capability",
                namespace="test/example",
                match_count=1,
                attack_ids=(),
                mbc_ids=(),
            ),
        ),
        timed_out=False,
        output_truncated=False,
        duration_seconds=0.1,
        stdout="{}",
        stderr="",
    )


def completed_floss_result(
    target: Path,
    scan_root: Path,
    **_: object,
) -> FlossResult:
    return FlossResult(
        status=FlossStatus.COMPLETED,
        complete=True,
        relative_path=(
            target.relative_to(scan_root).as_posix()
        ),
        return_code=0,
        strings=(
            FlossString(
                kind="decoded",
                value="synthetic string",
                encoding="ASCII",
                truncated=False,
            ),
        ),
        total_strings=1,
        strings_truncated=False,
        timed_out=False,
        output_truncated=False,
        duration_seconds=0.1,
        stdout="{}",
        stderr="",
    )


class AnalyzerDeduplicationTests(unittest.TestCase):
    @patch(
        "static_triage.capa.run_capa",
        side_effect=completed_capa_result,
    )
    def test_capa_runs_once_per_unique_hash(
        self,
        mocked_capa,
    ) -> None:
        entries = [
            binary_entry("a.exe", "a" * 64),
            binary_entry("copy/a.exe", "a" * 64),
            binary_entry("c.exe", "c" * 64),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            result = run_capa_batch(
                entries,
                Path(temporary),
                max_files=2,
            )

        self.assertEqual(
            result.status,
            CapaBatchStatus.COMPLETED,
        )
        self.assertTrue(result.complete)
        self.assertEqual(result.eligible_files, 3)
        self.assertEqual(result.unique_eligible_files, 2)
        self.assertEqual(result.attempted_files, 2)
        self.assertEqual(
            result.duplicate_analyses_avoided,
            1,
        )
        self.assertEqual(mocked_capa.call_count, 2)
        self.assertEqual(
            result.results[0].reused_for,
            ("copy/a.exe",),
        )

        payload = result.to_dict()
        self.assertEqual(payload["capability_count"], 2)
        self.assertEqual(
            payload["results"][0]["reused_for"],
            ["copy/a.exe"],
        )

    @patch(
        "static_triage.capa.run_capa",
        side_effect=completed_capa_result,
    )
    def test_capa_limit_counts_unique_hashes(
        self,
        mocked_capa,
    ) -> None:
        entries = [
            binary_entry("a.exe", "a" * 64),
            binary_entry("copy/a.exe", "a" * 64),
            binary_entry("c.exe", "c" * 64),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            result = run_capa_batch(
                entries,
                Path(temporary),
                max_files=1,
            )

        self.assertFalse(result.complete)
        self.assertEqual(result.attempted_files, 1)
        self.assertEqual(result.skipped_due_to_limit, 1)
        self.assertEqual(
            result.duplicate_analyses_avoided,
            1,
        )
        self.assertEqual(mocked_capa.call_count, 1)

    def test_unhashed_entries_are_not_deduplicated(
        self,
    ) -> None:
        selection = select_capa_entries(
            [
                binary_entry("a.exe", None),
                binary_entry("b.exe", None),
            ],
            max_files=10,
        )

        self.assertEqual(selection.eligible_count, 2)
        self.assertEqual(selection.unique_eligible_count, 2)
        self.assertEqual(len(selection.groups), 2)

    @patch(
        "static_triage.floss.run_floss",
        side_effect=completed_floss_result,
    )
    def test_floss_runs_once_per_unique_hash(
        self,
        mocked_floss,
    ) -> None:
        entries = [
            binary_entry("a.exe", "a" * 64),
            binary_entry("copy/a.exe", "a" * 64),
            binary_entry("c.exe", "c" * 64),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            result = run_floss_batch(
                entries,
                Path(temporary),
                max_files=2,
            )

        self.assertEqual(
            result.status,
            FlossBatchStatus.COMPLETED,
        )
        self.assertTrue(result.complete)
        self.assertEqual(result.eligible_files, 3)
        self.assertEqual(result.unique_eligible_files, 2)
        self.assertEqual(result.attempted_files, 2)
        self.assertEqual(
            result.duplicate_analyses_avoided,
            1,
        )
        self.assertEqual(mocked_floss.call_count, 2)
        self.assertEqual(
            result.results[0].reused_for,
            ("copy/a.exe",),
        )

        payload = result.to_dict()
        self.assertEqual(
            payload["extracted_string_count"],
            2,
        )
        self.assertEqual(payload["total_string_count"], 2)


if __name__ == "__main__":
    unittest.main()
