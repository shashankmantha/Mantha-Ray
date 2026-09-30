
    
  
"""Deterministic SHA-256 grouping for analyzer inputs."""

from __future__ import annotations

import os

from dataclasses import dataclass
from typing import Iterable

from .models import InventoryEntry


@dataclass(frozen=True, slots=True)
class AnalysisGroup:
    """Inventory entries that can share one analyzer execution."""

    representative: InventoryEntry
    entries: tuple[InventoryEntry, ...]

    @property
    def duplicate_count(self) -> int:
        """Return the number of executions avoided by this group."""

        return len(self.entries) - 1

    @property
    def reused_paths(self) -> tuple[str, ...]:
        """Return paths covered by the representative's result."""

        return tuple(
            entry.relative_path
            for entry in self.entries[1:]
        )


def group_entries_by_sha256(
    entries: Iterable[InventoryEntry],
) -> tuple[AnalysisGroup, ...]:
    """Group entries by hash while keeping unhashed paths separate.

    Inventory paths are sorted bytewise first, making both the selected
    representative and group order deterministic. An entry without a
    SHA-256 digest is deliberately keyed by path and is never assumed to
    be identical to another unhashed entry.
    """

    ordered = sorted(
        entries,
        key=lambda entry: os.fsencode(
            entry.relative_path
        ),
    )

    grouped: dict[
        tuple[str, str],
        list[InventoryEntry],
    ] = {}

    for entry in ordered:
        digest = (
            entry.sha256.strip().lower()
            if isinstance(entry.sha256, str)
            else ""
        )

        key = (
            ("sha256", digest)
            if digest
            else ("path", entry.relative_path)
        )

        grouped.setdefault(key, []).append(entry)

    return tuple(
        AnalysisGroup(
            representative=members[0],
            entries=tuple(members),
        )
        for members in grouped.values()
    )

