"""capa adapter for per-file static capability analysis."""

from __future__ import annotations

import json
import os 
import time

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .runner import CommandResult, run_command
from .models import (
    EntryKind,
    EntryState,
    InventoryEntry,
    RoutingClass,
)

from .capa_risk import (
    CapabilityRisk,
    CapaRiskSummary,
    assess_capability,
    summarize_risk,
)

class CapaBatchStatus(str, Enum):
    """Normalized outcome of the complete capa stage."""

    COMPLETED = "completed"
    PARTIAL = "partial"

class CapaStatus(str, Enum):
    """Normalized capa outcomes."""

    COMPLETED = "completed"
    ERROR = "error"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True, slots=True)
class CapaCapability:
    """One capability rule matched by capa."""

    name: str
    namespace: str | None
    match_count: int
    attack_ids: tuple[str, ...]
    mbc_ids: tuple[str, ...]

    @property
    def risk(self) -> CapabilityRisk:
        """Return the deterministic risk contribution for this rule."""

        return assess_capability(
            self.name,
            self.namespace,
            self.match_count,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "namespace": self.namespace,
            "match_count": self.match_count,
            "attack_ids": list(self.attack_ids),
            "mbc_ids": list(self.mbc_ids),
            "risk": self.risk.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class CapaResult:
    """Normalized result from one capa analysis."""

    status: CapaStatus
    complete: bool
    relative_path: str
    return_code: int
    capabilities: tuple[CapaCapability, ...]
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
            "relative_path": self.relative_path,
            "return_code": self.return_code,
            "capability_count": len(self.capabilities),
            "capabilities": [
                capability.to_dict()
                for capability in self.capabilities
            ],
            "risk": self.risk.to_dict(),
            "timed_out": self.timed_out,
            "output_truncated": self.output_truncated,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
            
        }
    
    @property
    def risk(self) -> CapaRiskSummary:
        """Summarize unique capa capabilities for this file."""

        return summarize_risk(
            capability.risk
            for capability in self.capabilities
        )

@dataclass(frozen=True, slots=True)
class CapaBatchResult:
    """Normalized result from the complete capa stage."""

    status: CapaBatchStatus
    complete: bool
    eligible_files: int
    attempted_files: int
    skipped_due_to_limit: int
    skipped_due_to_timeout: int
    results: tuple[CapaResult, ...]
    duration_seconds: float
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "complete": self.complete,
            "eligible_files": self.eligible_files,
            "attempted_files": self.attempted_files,
            "skipped_due_to_limit": (
                self.skipped_due_to_limit
            ),
            "skipped_due_to_timeout": (
                self.skipped_due_to_timeout
            ),
            "capability_count": sum(
                len(result.capabilities)
                for result in self.results
            ),
            "risk": self.risk.to_dict(),
            "results": [
                result.to_dict()
                for result in self.results
            ],
            "duration_seconds": self.duration_seconds,
            "error": self.error,
        }
    
    @property
    def risk(self) -> CapaRiskSummary:
        """Summarize unique capabilities across the analyzed case."""

        return summarize_risk(
            capability.risk
            for result in self.results
            for capability in result.capabilities
        )
    
@dataclass(frozen=True, slots=True)
class CapaSelection:
    """Deterministic selection of binaries for capa."""

    entries: tuple[InventoryEntry, ...]
    eligible_count: int
    skipped_due_to_limit: int

def _extract_framework_ids(
    entries: object,
) -> tuple[str, ...]:
    """Extract ATT&CK or MBC identifiers from capa metadata."""

    if not isinstance(entries, list):
        return ()

    identifiers: list[str] = []

    for entry in entries:
        identifier: str | None = None

        if isinstance(entry, dict):
            raw_identifier = entry.get("id")

            if isinstance(raw_identifier, str):
                identifier = raw_identifier.strip()

        elif isinstance(entry, str):
            _, separator, suffix = entry.rpartition("[")

            if separator and suffix.endswith("]"):
                identifier = suffix[:-1].strip()

        if identifier and identifier not in identifiers:
            identifiers.append(identifier)

    return tuple(identifiers)


def parse_capa_capabilities(
    output: str,
) -> tuple[CapaCapability, ...]:
    """Parse capa's JSON result document."""

    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"capa returned invalid JSON: {exc.msg}"
        ) from exc

    if not isinstance(payload, dict):
        raise ValueError(
            "capa JSON root must be an object"
        )

    rules = payload.get("rules")

    if not isinstance(rules, dict):
        raise ValueError(
            "capa JSON is missing its rules object"
        )

    capabilities: list[CapaCapability] = []

    for rule_key in sorted(rules):
        rule = rules[rule_key]

        if not isinstance(rule, dict):
            raise ValueError(
                f"capa rule {rule_key!r} is not an object"
            )

        metadata = rule.get("meta")
        matches = rule.get("matches")

        if not isinstance(metadata, dict):
            raise ValueError(
                f"capa rule {rule_key!r} has invalid metadata"
            )

        if not isinstance(matches, list):
            raise ValueError(
                f"capa rule {rule_key!r} has invalid matches"
            )

        # Library rules support other rules internally and should
        # not be presented as independent user-facing capabilities.
        if metadata.get("lib") is True:
            continue

        raw_name = metadata.get("name", rule_key)

        if not isinstance(raw_name, str) or not raw_name:
            raise ValueError(
                f"capa rule {rule_key!r} has an invalid name"
            )

        raw_namespace = metadata.get("namespace")

        if (
            raw_namespace is not None
            and not isinstance(raw_namespace, str)
        ):
            raise ValueError(
                f"capa rule {rule_key!r} has an invalid namespace"
            )

        capabilities.append(
            CapaCapability(
                name=raw_name,
                namespace=raw_namespace,
                match_count=len(matches),
                attack_ids=_extract_framework_ids(
                    metadata.get("att&ck")
                ),
                mbc_ids=_extract_framework_ids(
                    metadata.get("mbc")
                ),
            )
        )

    return tuple(capabilities)


def _normalize_result(
    execution: CommandResult,
    relative_path: str,
) -> CapaResult:
    """Convert an external command result into a capa result."""

    issues: list[str] = []
    capabilities: tuple[CapaCapability, ...] = ()

    if execution.timed_out:
        status = CapaStatus.TIMED_OUT
        issues.append("capa exceeded its timeout")

    elif execution.return_code != 0:
        status = CapaStatus.ERROR
        issues.append(
            "capa exited with unexpected code "
            f"{execution.return_code}"
        )

    else:
        try:
            capabilities = parse_capa_capabilities(
                execution.stdout
            )
        except ValueError as exc:
            status = CapaStatus.ERROR
            issues.append(str(exc))
        else:
            status = CapaStatus.COMPLETED

    if execution.output_truncated:
        issues.append("capa output exceeded its limit")

        if status == CapaStatus.COMPLETED:
            status = CapaStatus.ERROR

    complete = (
        status == CapaStatus.COMPLETED
        and not execution.timed_out
        and not execution.output_truncated
    )

    return CapaResult(
        status=status,
        complete=complete,
        relative_path=relative_path,
        return_code=execution.return_code,
        capabilities=capabilities,
        timed_out=execution.timed_out,
        output_truncated=execution.output_truncated,
        duration_seconds=execution.duration_seconds,
        stdout=execution.stdout,
        stderr=execution.stderr,
        error="; ".join(issues) or None,
    )

def run_capa(
    target: Path,
    scan_root: Path,
    *,
    executable: str = "capa",
    timeout_seconds: float = 300.0,
    max_output_bytes: int = 16_000_000,
) -> CapaResult:
    """Analyze one inventory-approved binary with capa."""

    if not target.is_absolute():
        raise ValueError(
            "capa target must be absolute"
        )

    if not scan_root.is_absolute():
        raise ValueError(
            "capa scan root must be absolute"
        )

    try:
        relative = target.relative_to(
            scan_root
        )
    except ValueError as exc:
        raise ValueError(
            "capa target must be beneath the scan root"
        ) from exc

    if ".." in relative.parts:
        raise ValueError(
            "capa target must be beneath the scan root"
        )

    if target.is_symlink():
        raise ValueError(
            "capa target cannot be a symlink"
        )

    if not target.is_file():
        raise ValueError(
            "capa target must be a regular file"
        )

    rules_arguments: list[str] = []

    configured_rules = os.environ.get(
        "CAPA_RULES_PATH"
    )

    if configured_rules:
        rules_directory = Path(
            configured_rules
        )

        if not rules_directory.is_absolute():
            raise ValueError(
                "capa rules path must be absolute"
            )

        if not rules_directory.is_dir():
            raise ValueError(
                "capa rules path must be a directory"
            )

        rules_arguments = [
            "-r",
            str(rules_directory),
        ]

    signature_arguments: list[str] = []

    configured_signatures = os.environ.get(
        "CAPA_SIGNATURES_PATH"
    )

    if configured_signatures:
        signatures_directory = Path(
            configured_signatures
        )

        if not signatures_directory.is_absolute():
            raise ValueError(
                "capa signatures path must be absolute"
            )

        if not signatures_directory.is_dir():
            raise ValueError(
                "capa signatures path must be a directory"
            )

        signature_arguments = [
            "-s",
            str(signatures_directory),
        ]

    command = [
        executable,
        *rules_arguments,
        *signature_arguments,
        "-j",
        "--color",
        "never",
        str(target),
    ]

    execution = run_command(
        command,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        env={
            "PATH": (
                "/opt/capa-venv/bin:"
                "/usr/local/bin:/usr/bin:/bin"
            ),
            "LC_ALL": "C",
            "LANG": "C",
            "HOME": "/tmp/capa-home",
            "XDG_CACHE_HOME": "/tmp/capa-cache",
            "XDG_CONFIG_HOME": "/tmp/capa-config",
            "USER": "static-triage",
            "LOGNAME": "static-triage",
        },
    )

    return _normalize_result(
        execution,
        relative.as_posix(),
    )

_CAPA_ROUTING_CLASSES = frozenset(
    {
        RoutingClass.PE_EXECUTABLE,
        RoutingClass.PE_DLL,
        RoutingClass.ELF,
    }
)

def select_capa_entries(
    entries: list[InventoryEntry],
    *,
    max_files: int,
) -> CapaSelection:
    """Select inventory-approved binaries for capa."""

    if max_files <= 0:
        raise ValueError(
            "maximum capa file count must be positive"
        )

    eligible = [
        entry
        for entry in entries
        if (
            entry.kind == EntryKind.REGULAR_FILE
            and entry.state == EntryState.INVENTORIED
            and entry.routing_class
            in _CAPA_ROUTING_CLASSES
        )
    ]

    eligible.sort(
        key=lambda entry: os.fsencode(
            entry.relative_path
        )
    )

    selected = eligible[:max_files]

    return CapaSelection(
        entries=tuple(selected),
        eligible_count=len(eligible),
        skipped_due_to_limit=(
            len(eligible) - len(selected)
        ),
    )


def run_capa_batch(
    entries: list[InventoryEntry],
    scan_root: Path,
    *,
    executable: str = "capa",
    max_files: int = 250,
    file_timeout_seconds: float = 300.0,
    total_timeout_seconds: float = 3600.0,
    max_output_bytes: int = 16_000_000,
) -> CapaBatchResult:
    """Run capa over a bounded set of eligible binaries."""

    if total_timeout_seconds <= 0:
        raise ValueError(
            "capa total timeout must be positive"
        )

    if file_timeout_seconds <= 0:
        raise ValueError(
            "capa file timeout must be positive"
        )

    if max_output_bytes <= 0:
        raise ValueError(
            "capa output limit must be positive"
        )

    selection = select_capa_entries(
        entries,
        max_files=max_files,
    )

    started = time.monotonic()
    results: list[CapaResult] = []

    for entry in selection.entries:
        elapsed = time.monotonic() - started
        remaining = total_timeout_seconds - elapsed

        if remaining <= 0:
            break

        effective_timeout = min(
            file_timeout_seconds,
            remaining,
        )

        file_target = (
            scan_root
            / Path(entry.relative_path)
        )

        try:
            result = run_capa(
                file_target,
                scan_root,
                executable=executable,
                timeout_seconds=effective_timeout,
                max_output_bytes=max_output_bytes,
            )
        except (OSError, ValueError) as exc:
            result = CapaResult(
                status=CapaStatus.ERROR,
                complete=False,
                relative_path=entry.relative_path,
                return_code=-1,
                capabilities=(),
                timed_out=False,
                output_truncated=False,
                duration_seconds=0.0,
                stdout="",
                stderr="",
                error=(
                    "capa analysis could not start: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

        results.append(result)

    skipped_due_to_timeout = (
        len(selection.entries) - len(results)
    )

    issues: list[str] = []

    if selection.skipped_due_to_limit:
        issues.append(
            f"{selection.skipped_due_to_limit} eligible "
            "files exceeded the capa file-count limit"
        )

    if skipped_due_to_timeout:
        issues.append(
            f"{skipped_due_to_timeout} selected files "
            "were not analyzed before the capa "
            "total-time limit"
        )

    failed_files = sum(
        not result.complete
        for result in results
    )

    if failed_files:
        issues.append(
            f"{failed_files} capa analyses were incomplete"
        )

    complete = (
        selection.skipped_due_to_limit == 0
        and skipped_due_to_timeout == 0
        and failed_files == 0
    )

    return CapaBatchResult(
        status=(
            CapaBatchStatus.COMPLETED
            if complete
            else CapaBatchStatus.PARTIAL
        ),
        complete=complete,
        eligible_files=selection.eligible_count,
        attempted_files=len(results),
        skipped_due_to_limit=(
            selection.skipped_due_to_limit
        ),
        skipped_due_to_timeout=(
            skipped_due_to_timeout
        ),
        results=tuple(results),
        duration_seconds=(
            time.monotonic() - started
        ),
        error="; ".join(issues) or None,
    )