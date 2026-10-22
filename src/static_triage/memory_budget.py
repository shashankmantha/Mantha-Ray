from __future__ import annotations

from collections.abc import Sequence

MIB = 1024**2

# Memory kept back for the scanner itself, outside capa and FLOSS.
SCANNER_OVERHEAD_MIB = 256

# Rough peak memory per analysis, by file size, used only to decide which
# analyses can run at the same time. They are deliberately conservative
# and never stop a file from being analyzed: a file whose estimate exceeds
# the budget runs alone instead. Measured on Door Kickers 2 (2026-10-20/21):
# capa peaked near 4 GiB on 6.8-8.2 MB executables; FLOSS ran out of
# memory on a pair of ~300 KB files in 4 GiB, and used several GiB on
# 1-3 MB libraries. Tune these from the peak_memory_mib that reports now
# record for every analysis.
_ESTIMATES: dict[str, Sequence[tuple[int | None, int]]] = {
    "capa": (
        (1 * MIB, 768),
        (4 * MIB, 1536),
        (None, 3584),
    ),
    "floss": (
        (1 * MIB, 2048),
        (4 * MIB, 3072),
        (None, 4096),
    ),
}


def estimate_mib(analyzer: str, size_bytes: object) -> int:
    tiers = _ESTIMATES[analyzer]
    if not isinstance(size_bytes, int) or isinstance(size_bytes, bool):
        return tiers[-1][1]
    for limit, estimate in tiers:
        if limit is None or size_bytes <= limit:
            return estimate
    return tiers[-1][1]


def analysis_budget_mib(container_memory_mib: int) -> int:
    return max(256, container_memory_mib - SCANNER_OVERHEAD_MIB)


def memory_policy(analyzer: str, budget_mib: int) -> dict[str, object]:
    return {
        "budget_mib": budget_mib,
        "estimates": [
            {"up_to_bytes": limit, "estimate_mib": estimate}
            for limit, estimate in _ESTIMATES[analyzer]
        ],
    }