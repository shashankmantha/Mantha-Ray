"""Stable data models for scanner inventory and reporting."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


SCHEMA_VERSION = "0.1.0"


class RoutingClass(StrEnum):
    """High-level file categories used to select analysis tools."""

    PE_EXECUTABLE = "pe_executable"
    PE_DLL = "pe_dll"
    ELF = "elf"
    SCRIPT = "script"
    ARCHIVE = "archive"
    DOCUMENT = "document"
    MEDIA = "media"
    TEXT = "text"
    OTHER = "other"
    EMPTY = "empty"


class EntryKind(StrEnum):
    """Filesystem entry types encountered during inventory."""

    REGULAR_FILE = "regular_file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    FIFO = "fifo"
    SOCKET = "socket"
    DEVICE = "device"
    OTHER = "other"


class EntryState(StrEnum):
    """Outcome of processing one filesystem entry."""

    INVENTORIED = "inventoried"
    SKIPPED = "skipped"
    ERROR = "error"
    LIMIT_EXCEEDED = "limit_exceeded"


class OverallStatus(StrEnum):
    """Final deterministic case classifications."""

    KNOWN_DETECTION = "known_detection"
    HIGH_CONCERN = "high_concern"
    NEEDS_REVIEW = "needs_review"
    NO_INDICATORS_DETECTED = "no_indicators_detected"
    INCOMPLETE = "incomplete"


@dataclass(slots=True)
class InventoryEntry:
    """Normalized information about one filesystem entry."""

    relative_path: str
    kind: EntryKind
    state: EntryState
    size_bytes: int | None = None
    mode: str | None = None
    sha256: str | None = None
    detected_type: str | None = None
    routing_class: RoutingClass | None = None
    evidence: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ToolInfo:
    """Availability and version information for an analysis tool."""

    name: str
    executable: str | None
    available: bool
    version: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class InventorySummary:
    """Case-wide counters calculated from the inventory."""

    regular_files: int = 0
    skipped_entries: int = 0
    errors: int = 0
    limit_exceeded: int = 0
    total_bytes: int = 0
    hashed_files: int = 0
    supported_binaries: int = 0
    review_flags: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)