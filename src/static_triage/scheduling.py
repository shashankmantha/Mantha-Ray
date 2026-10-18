"""Order in which analyzers spend their time budgets.

capa and FLOSS run one file at a time against a total time budget, so
the order decides which files get analyzed when the budget runs out.
Small files first: they usually finish in seconds, while the largest
binaries are the ones most likely to time out. Crack loaders and
replaced DLLs are typically small, so they are reached early instead
of whenever they happen to sort alphabetically.

Results are still reported in path order so reports stay comparable.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from typing import Protocol, TypeVar

from .deduplication import AnalysisGroup

SCHEDULING_POLICY = "smallest-first"


class _HasRelativePath(Protocol):
    relative_path: str


ResultT = TypeVar("ResultT", bound=_HasRelativePath)


def _priority(group: AnalysisGroup) -> tuple[int, int, bytes]:
    entry = group.representative
    size = entry.size_bytes
    known = (
        isinstance(size, int)
        and not isinstance(size, bool)
        and size >= 0
    )
    # Unknown sizes go last; ties break on the path bytes so the order
    # is identical on every run.
    return (
        0 if known else 1,
        size if known else 0,
        os.fsencode(entry.relative_path),
    )


def prioritize_groups(
    groups: Iterable[AnalysisGroup],
) -> tuple[AnalysisGroup, ...]:
    """Return analysis groups in the order they should be analyzed."""

    return tuple(sorted(groups, key=_priority))


def in_path_order(results: Iterable[ResultT]) -> tuple[ResultT, ...]:
    """Return results sorted by path for stable reporting."""

    return tuple(
        sorted(results, key=lambda result: os.fsencode(result.relative_path))
    )