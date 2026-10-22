from __future__ import annotations

from collections.abc import Callable, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Generic, TypeVar

from .deduplication import AnalysisGroup
from .file_progress import (
    FileProgress,
    finished_message,
    memory_retry_message,
    started_message,
)

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


# Exit codes of a process killed with SIGKILL: what the kernel's
# out-of-memory killer uses when the container hits its memory limit.
MEMORY_KILL_CODES = frozenset({-9, 137})

# Only start a file when enough budget is left for it to be useful:
# a quarter of its limit, at least a minute, never more than its limit or
# half the whole budget. Otherwise it counts as not reached.
MIN_START_FRACTION = 0.25
MIN_START_SECONDS = 60.0


def looks_memory_killed(return_code: int, timed_out: bool) -> bool:
    return not timed_out and return_code in MEMORY_KILL_CODES


def minimum_start_seconds(limit: float, total_budget: float) -> float:
    wanted = max(MIN_START_SECONDS, MIN_START_FRACTION * limit)
    return min(limit, wanted, total_budget / 2)


@dataclass(frozen=True, slots=True)
class Finished(Generic[R]):
    group: AnalysisGroup
    result: R
    position: int
    timeout_seconds: float
    # The size-scaled limit before the stage budget capped it.
    limit_seconds: float = 0.0
    # The memory-killed first attempt, when this result is a solo retry.
    first_attempt: R | None = None
    # Whether another analysis ran at the same time as this one.
    shared: bool = False
    # Memory reserved for this analysis when it started, if budgeted.
    memory_estimate_mib: int | None = None

    @property
    def capped_by_budget(self) -> bool:
        return self.timeout_seconds < self.limit_seconds - 1e-6


@dataclass(frozen=True, slots=True)
class PoolRun(Generic[R]):
    finished: tuple[Finished[R], ...]
    not_started: tuple[AnalysisGroup, ...]


@dataclass(slots=True)
class _Job:
    group: AnalysisGroup
    position: int
    timeout: float
    limit: float
    alone: bool = False
    shared: bool = False
    first_attempt: object = None
    reserve: int = 0
    estimate: int | None = None


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
    retry_alone_if: Callable[[R], bool] | None = None,
    memory_budget_mib: int | None = None,
    memory_for: Callable[[AnalysisGroup], int] | None = None,
) -> PoolRun[R]:
    # Groups start in priority order while the stage budget lasts. Each
    # file's timeout is capped by the budget left when it starts, so the
    # stage cannot overrun. A file killed for memory while sharing the
    # container is retried once with nothing else running. With a memory
    # budget, a file only starts when its estimate fits beside the running
    # ones; a file estimated above the whole budget runs alone. Progress
    # callbacks run on this thread only.
    if workers < 1:
        raise ValueError(f"{label} needs at least one worker")

    total = len(groups)
    started = clock() if started_at is None else started_at
    pending: dict[Future[R], _Job] = {}
    finished: list[Finished[R]] = []
    retries: list[_Job] = []
    next_index = 0
    out_of_time = False

    def reserved() -> int:
        return sum(job.reserve for job in pending.values())

    def remaining() -> float:
        return total_timeout_seconds - (clock() - started)

    def emit(message: str) -> None:
        if on_file is not None:
            on_file(message)

    def submit(pool: ThreadPoolExecutor, job: _Job) -> None:
        if pending:
            job.shared = True
            for other in pending.values():
                other.shared = True
        pending[pool.submit(analyze, job.group, job.timeout)] = job

    def record(job: _Job, result: R, first_attempt: R | None = None) -> None:
        finished.append(
            Finished(
                job.group,
                result,
                job.position,
                job.timeout,
                job.limit,
                first_attempt,
                job.shared,
                job.estimate,
            )
        )
        complete, timed_out, seconds = outcome(result)
        emit(
            finished_message(
                label,
                job.position,
                total,
                job.group,
                complete=complete,
                timed_out=timed_out,
                duration_seconds=seconds,
                stopped_at_budget_end=(
                    timed_out and job.timeout < job.limit - 1e-6
                ),
            )
        )

    with ThreadPoolExecutor(
        max_workers=workers,
        thread_name_prefix=f"{label}-worker",
    ) as pool:
        while True:
            if retries:
                # A retry waits until everything else has finished.
                if not pending:
                    job = retries.pop(0)
                    left = remaining()
                    if left >= minimum_start_seconds(
                        job.limit, total_timeout_seconds
                    ):
                        retry = _Job(
                            job.group,
                            job.position,
                            min(job.limit, left),
                            job.limit,
                            alone=True,
                            first_attempt=job.first_attempt,
                            reserve=memory_budget_mib or 0,
                            estimate=job.estimate,
                        )
                        emit(
                            started_message(
                                label, job.position, total, job.group,
                                alone=True,
                            )
                        )
                        submit(pool, retry)
                    else:
                        # No time left to retry: keep the first attempt.
                        record(job, job.first_attempt)  # type: ignore[arg-type]
                    continue
            else:
                while (
                    not out_of_time
                    and len(pending) < workers
                    and next_index < total
                ):
                    group = groups[next_index]
                    limit = timeout_for(group)
                    left = remaining()
                    if left < minimum_start_seconds(
                        limit, total_timeout_seconds
                    ) or left <= 0:
                        # Later files are no smaller, so stop starting.
                        out_of_time = True
                        break
                    estimate = None
                    reserve = 0
                    if memory_budget_mib is not None and memory_for is not None:
                        estimate = memory_for(group)
                        reserve = min(estimate, memory_budget_mib)
                        if pending and reserved() + reserve > memory_budget_mib:
                            # Wait for memory; later files need no less.
                            break
                    next_index += 1
                    job = _Job(
                        group,
                        next_index,
                        min(limit, left),
                        limit,
                        reserve=reserve,
                        estimate=estimate,
                    )
                    alone = (
                        memory_budget_mib is not None
                        and estimate is not None
                        and estimate >= memory_budget_mib
                    )
                    emit(
                        started_message(
                            label, next_index, total, group, alone=alone
                        )
                    )
                    submit(pool, job)

            if not pending:
                if retries:
                    continue
                break

            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in sorted(done, key=lambda item: pending[item].position):
                job = pending.pop(future)
                result = future.result()
                if (
                    retry_alone_if is not None
                    and job.shared
                    and not job.alone
                    and retry_alone_if(result)
                ):
                    seconds = outcome(result)[2]
                    emit(
                        memory_retry_message(
                            label, job.position, total, job.group, seconds
                        )
                    )
                    job.first_attempt = result
                    retries.append(job)
                    continue
                record(job, result, job.first_attempt)  # type: ignore[arg-type]

    return PoolRun(
        finished=tuple(finished),
        not_started=tuple(groups[next_index:]),
    )