from __future__ import annotations

from collections.abc import Callable, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Generic, TypeVar

from .deduplication import AnalysisGroup
from .file_progress import FileProgress, finished_message, started_message

R = TypeVar("R")

# Files up to this size get the plain per-file timeout. Larger files get
# proportionally more time, up to the large-file cap.
TIMEOUT_REFERENCE_BYTES = 1024**2


def scaled_timeout(
    size_bytes: object,
    *,
    base_seconds: float,
    max_seconds: float,
) -> float:
    if (
        not isinstance(size_bytes, int)
        or isinstance(size_bytes, bool)
        or size_bytes <= TIMEOUT_REFERENCE_BYTES
        or max_seconds <= base_seconds
    ):
        return base_seconds
    scaled = base_seconds * size_bytes / TIMEOUT_REFERENCE_BYTES
    return min(max_seconds, scaled)


def timeout_policy(base_seconds: float, max_seconds: float) -> dict[str, float]:
    return {
        "base_seconds": base_seconds,
        "max_seconds": max(base_seconds, max_seconds),
        "reference_bytes": TIMEOUT_REFERENCE_BYTES,
    }


@dataclass(frozen=True, slots=True)
class Finished(Generic[R]):
    group: AnalysisGroup
    result: R
    position: int
    timeout_seconds: float


@dataclass(frozen=True, slots=True)
class PoolRun(Generic[R]):
    finished: tuple[Finished[R], ...]
    not_started: tuple[AnalysisGroup, ...]


def run_groups(
    groups: Sequence[AnalysisGroup],
    analyze: Callable[[AnalysisGroup, float], R],
    *,
    label: str,
    workers: int,
    total_timeout_seconds: float,
    timeout_for: Callable[[AnalysisGroup], float],
    outcome: Callable[[R], tuple[bool, bool, float]],
    clock: Callable[[], float],
    started_at: float | None = None,
    on_file: FileProgress | None = None,
) -> PoolRun[R]:
    # Groups start in priority order while the stage budget lasts. Each
    # file's timeout is capped by the budget left when it starts, so the
    # stage cannot overrun. Progress callbacks run on this thread only.
    if workers < 1:
        raise ValueError(f"{label} needs at least one worker")

    total = len(groups)
    started = clock() if started_at is None else started_at
    pending: dict[Future[R], tuple[AnalysisGroup, int, float]] = {}
    finished: list[Finished[R]] = []
    next_index = 0
    out_of_time = False

    with ThreadPoolExecutor(
        max_workers=workers,
        thread_name_prefix=f"{label}-worker",
    ) as pool:
        while True:
            while (
                not out_of_time
                and len(pending) < workers
                and next_index < total
            ):
                remaining = total_timeout_seconds - (clock() - started)
                if remaining <= 0:
                    out_of_time = True
                    break
                group = groups[next_index]
                next_index += 1
                timeout = min(timeout_for(group), remaining)
                if on_file is not None:
                    on_file(started_message(label, next_index, total, group))
                future = pool.submit(analyze, group, timeout)
                pending[future] = (group, next_index, timeout)

            if not pending:
                break

            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in sorted(done, key=lambda item: pending[item][1]):
                group, position, timeout = pending.pop(future)
                result = future.result()
                finished.append(Finished(group, result, position, timeout))
                if on_file is not None:
                    complete, timed_out, seconds = outcome(result)
                    on_file(
                        finished_message(
                            label,
                            position,
                            total,
                            group,
                            complete=complete,
                            timed_out=timed_out,
                            duration_seconds=seconds,
                        )
                    )

    return PoolRun(
        finished=tuple(finished),
        not_started=tuple(groups[next_index:]),
    )