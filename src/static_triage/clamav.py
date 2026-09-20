"""ClamAV adapter for recursive static scanning."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .runner import CommandResult, run_command


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

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "complete": self.complete,
            "return_code": self.return_code,
            "findings": [
                finding.to_dict()
                for finding in self.findings
            ],
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

    findings = parse_clamav_findings(
        execution.stdout,
        target,
    )

    issues: list[str] = []

    if execution.timed_out:
        status = ClamAVStatus.TIMED_OUT
        issues.append("ClamAV exceeded its timeout")

    elif execution.return_code == 0:
        status = ClamAVStatus.CLEAN

    elif execution.return_code == 1:
        status = ClamAVStatus.INFECTED

        if not findings:
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

    complete = (
        not execution.timed_out
        and not execution.output_truncated
        and execution.return_code in {0, 1}
        and not (
            execution.return_code == 1
            and not findings
        )
    )

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
        env={
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LC_ALL": "C",
            "LANG": "C",
        },
    )

    return _normalize_result(
        execution,
        target,
    )