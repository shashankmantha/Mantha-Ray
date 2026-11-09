from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import stop_request
from .models import EntryKind, EntryState, InventoryEntry

CHUNK_BYTES = 1024 * 1024
MAX_LISTED = 200


@dataclass(frozen=True, slots=True)
class IntegrityResult:
    """Every hashed file, hashed again after analysis and compared."""

    checked: int
    changed: tuple[str, ...] = ()
    unreadable: tuple[str, ...] = ()
    skipped: bool = False
    duration_seconds: float = 0.0
    note: str | None = field(default=None)

    @property
    def ok(self) -> bool:
        return not self.skipped and not self.changed and not self.unreadable

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked": self.checked,
            "ok": self.ok,
            "changed_count": len(self.changed),
            "changed": list(self.changed[:MAX_LISTED]),
            "unreadable_count": len(self.unreadable),
            "unreadable": list(self.unreadable[:MAX_LISTED]),
            "skipped": self.skipped,
            "duration_seconds": round(self.duration_seconds, 3),
            "note": self.note,
        }


def _sha256(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        digest = hashlib.sha256()
        while chunk := os.read(fd, CHUNK_BYTES):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(fd)


def verify_hashes(entries: list[InventoryEntry], target: Path) -> IntegrityResult:
    """Re-hash every inventoried file and report any that changed during the scan.

    The scan reads a read-only mount and never runs anything, so a change can
    only come from outside the container (the folder being modified while it
    was scanned). Results for a changed file describe a different file, so the
    report says so instead of trusting them.
    """

    started = time.monotonic()
    changed: list[str] = []
    unreadable: list[str] = []
    checked = 0
    for entry in entries:
        if (
            entry.kind != EntryKind.REGULAR_FILE
            or entry.state != EntryState.INVENTORIED
            or not entry.sha256
        ):
            continue
        if stop_request.requested():
            return IntegrityResult(
                checked=checked, changed=tuple(changed), unreadable=tuple(unreadable),
                skipped=True, duration_seconds=time.monotonic() - started,
                note="the scan was stopped before every file was re-checked",
            )
        try:
            current = _sha256(target / entry.relative_path)
        except OSError:
            unreadable.append(entry.relative_path)
            continue
        checked += 1
        if current != entry.sha256:
            changed.append(entry.relative_path)
    return IntegrityResult(
        checked=checked,
        changed=tuple(changed),
        unreadable=tuple(unreadable),
        duration_seconds=time.monotonic() - started,
    )
