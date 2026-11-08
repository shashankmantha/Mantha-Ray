"""ClamAV adapter for recursive static scanning."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any

from .runner import CommandResult, run_command
from .stop_request import STOPPED_MESSAGE

# clamscan's defaults skip files over 100 MB and stop after 400 MB per file or
# archive, and treat what they skip as clean without saying so. These raise
# the limits to what libclamav supports (just under 2 GiB) and make anything
# still over a limit an alert, which is reported as not covered, never as a
# detection.
MAX_FILE_MIB = 2047
MAX_SCAN_MIB = 2047
MAX_SCAN_TIME_MS = 10 * 60 * 1000
LIMIT_ALERT_PREFIX = "Heuristics.Limits.Exceeded."
LIMIT_REASONS = {
    "MaxFileSize": f"larger than ClamAV can scan ({MAX_FILE_MIB} MiB)",
    "MaxScanSize": f"more than {MAX_SCAN_MIB} MiB of data inside it",
    "MaxScanTime": f"took longer than {MAX_SCAN_TIME_MS // 60000} minutes to scan",
    "MaxFiles": "too many files inside the archive",
    "MaxRecursion": "archives nested too deeply",
}
# A recursive scan gets 15 minutes plus 3 minutes per GiB of files, up to 4 hours.
BASE_TIMEOUT_SECONDS = 15 * 60
TIMEOUT_SECONDS_PER_GIB = 3 * 60
MAX_TIMEOUT_SECONDS = 4 * 60 * 60


def scan_timeout_seconds(total_bytes: int | None) -> float:
    if not isinstance(total_bytes, int) or isinstance(total_bytes, bool) or total_bytes <= 0:
        return float(BASE_TIMEOUT_SECONDS)
    extra = TIMEOUT_SECONDS_PER_GIB * total_bytes / 1024**3
    return float(min(MAX_TIMEOUT_SECONDS, BASE_TIMEOUT_SECONDS + extra))


class ClamAVStatus(str, Enum):
    """Normalized ClamAV outcomes."""

    CLEAN = "clean"
    INFECTED = "infected"
    ERROR = "error"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True, slots=True)
class ClamAVFinding:
    """One signature match reported by ClamAV."""

    relative_path: str
    signature: str

    def to_dict(self) -> dict[str, str]:
        return {
            "relative_path": self.relative_path,
            "signature": self.signature,
        }


@dataclass(frozen=True, slots=True)
class ClamAVLimitHit:
    """A file ClamAV didn't scan completely because it hit a limit."""

    relative_path: str
    limit: str

    @property
    def reason(self) -> str:
        return LIMIT_REASONS.get(self.limit, f"over ClamAV's {self.limit} limit")

    def to_dict(self) -> dict[str, str]:
        return {
            "relative_path": self.relative_path,
            "limit": self.limit,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class ClamAVResult:
    """Normalized result from one ClamAV scan."""

    status: ClamAVStatus
    complete: bool
    return_code: int
    findings: tuple[ClamAVFinding, ...]
    timed_out: bool
    output_truncated: bool
    duration_seconds: float
    stdout: str
    stderr: str
    error: str | None = None
    limits_exceeded: tuple[ClamAVLimitHit, ...] = ()
    timeout_seconds: float | None = None
    # Whether clamscan finished its run, ignoring files it hit limits on.
    # None means the same as complete (results made before this existed).
    run_complete: bool | None = None
    stopped_by_user: bool = False

    @property
    def whole_run_complete(self) -> bool:
        return self.complete if self.run_complete is None else self.run_complete

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "complete": self.complete,
            "return_code": self.return_code,
            "findings": [
                finding.to_dict()
                for finding in self.findings
            ],
            "limits_exceeded": [
                hit.to_dict()
                for hit in self.limits_exceeded
            ],
            "limits": {
                "max_file_mib": MAX_FILE_MIB,
                "max_scan_mib": MAX_SCAN_MIB,
                "max_scan_time_seconds": MAX_SCAN_TIME_MS // 1000,
                "timeout_seconds": self.timeout_seconds,
            },
            "timed_out": self.timed_out,
            "output_truncated": self.output_truncated,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
        }


def parse_clamav_findings(
    output: str,
    target: Path,
) -> tuple[ClamAVFinding, ...]:
    """Extract infection records from ClamAV text output."""

    findings: list[ClamAVFinding] = []

    for line in output.splitlines():
        if not line.endswith(" FOUND"):
            continue

        finding_text = line[:-len(" FOUND")]
        raw_path, separator, signature = (
            finding_text.rpartition(": ")
        )

        if not separator or not raw_path or not signature:
            continue

        reported_path = Path(raw_path)

        try:
            relative_path = reported_path.relative_to(
                target
            ).as_posix()
        except ValueError:
            relative_path = raw_path

        findings.append(
            ClamAVFinding(
                relative_path=relative_path,
                signature=signature,
            )
        )

    return tuple(findings)


def _normalize_result(
    execution: CommandResult,
    target: Path,
) -> ClamAVResult:
    """Convert a command result into a ClamAV result."""

    parsed = parse_clamav_findings(
        execution.stdout,
        target,
    )
    findings = tuple(
        finding for finding in parsed
        if not finding.signature.startswith(LIMIT_ALERT_PREFIX)
    )
    limit_hits = tuple(
        ClamAVLimitHit(
            relative_path=finding.relative_path,
            limit=finding.signature[len(LIMIT_ALERT_PREFIX):].split(".")[0] or "unknown",
        )
        for finding in parsed
        if finding.signature.startswith(LIMIT_ALERT_PREFIX)
    )

    issues: list[str] = []

    if execution.stopped:
        status = ClamAVStatus.ERROR
        issues.append("ClamAV did not finish: " + STOPPED_MESSAGE)

    elif execution.timed_out:
        status = ClamAVStatus.TIMED_OUT
        issues.append("ClamAV exceeded its timeout")

    elif execution.return_code == 0:
        status = ClamAVStatus.CLEAN

    elif execution.return_code == 1 and findings:
        status = ClamAVStatus.INFECTED

    elif execution.return_code == 1 and limit_hits:
        # Only limit alerts: nothing was detected, but some files weren't
        # scanned completely.
        status = ClamAVStatus.CLEAN

    elif execution.return_code == 1:
        status = ClamAVStatus.INFECTED
        issues.append(
            "ClamAV reported an infection but no "
            "finding could be parsed"
        )

    else:
        status = ClamAVStatus.ERROR
        issues.append(
            "ClamAV exited with unexpected code "
            f"{execution.return_code}"
        )

    if execution.output_truncated:
        issues.append("ClamAV output exceeded its limit")

    if limit_hits:
        count = len(limit_hits)
        issues.append(
            f"{count} {'file was' if count == 1 else 'files were'} not fully "
            "scanned by ClamAV (over its size or time limits)"
        )

    run_complete = (
        not execution.stopped
        and not execution.timed_out
        and not execution.output_truncated
        and execution.return_code in {0, 1}
        and not (
            execution.return_code == 1
            and not findings
            and not limit_hits
        )
    )
    complete = run_complete and not limit_hits

    return ClamAVResult(
        status=status,
        complete=complete,
        return_code=execution.return_code,
        findings=findings,
        timed_out=execution.timed_out,
        output_truncated=execution.output_truncated,
        duration_seconds=execution.duration_seconds,
        stdout=execution.stdout,
        stderr=execution.stderr,
        error="; ".join(issues) or None,
        limits_exceeded=limit_hits,
        run_complete=run_complete,
        stopped_by_user=bool(execution.stopped),
    )


def run_clamav(
    target: Path,
    *,
    executable: str = "clamscan",
    timeout_seconds: float = 900.0,
    max_output_bytes: int = 2_000_000,
    max_signature_age_days: int = 7,
) -> ClamAVResult:
    """Recursively scan a validated staging directory."""

    if not target.is_absolute():
        raise ValueError("ClamAV target must be absolute")

    if max_signature_age_days <= 0:
        raise ValueError(
            "max_signature_age_days must be positive"
        )

    command = [
        executable,
        "--recursive=yes",
        "--infected",
        "--stdout",
        "--alert-exceeds-max=yes",
        f"--max-filesize={MAX_FILE_MIB}M",
        f"--max-scansize={MAX_SCAN_MIB}M",
        f"--max-scantime={MAX_SCAN_TIME_MS}",
        "--cross-fs=no",
        "--follow-dir-symlinks=0",
        "--follow-file-symlinks=0",
        (
            "--fail-if-cvd-older-than="
            f"{max_signature_age_days}"
        ),
        str(target),
    ]

    execution = run_command(
        command,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        stoppable=True,
        env={
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LC_ALL": "C",
            "LANG": "C",
        },
    )

    result = _normalize_result(
        execution,
        target,
    )
    return replace(result, timeout_seconds=timeout_seconds)