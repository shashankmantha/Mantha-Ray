"""Safe directory traversal, content routing, and hashing."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from .config import ScanLimits
from .filetypes import (
    detect_type,
    filename_evidence,
    open_regular_nofollow,
)
from .models import (
    EntryKind,
    EntryState,
    InventoryEntry,
    InventorySummary,
    RoutingClass,
)


def _entry_kind(mode: int) -> EntryKind:
    """Convert a Unix file mode into a normalized entry type."""

    if stat.S_ISREG(mode):
        return EntryKind.REGULAR_FILE

    if stat.S_ISDIR(mode):
        return EntryKind.DIRECTORY

    if stat.S_ISLNK(mode):
        return EntryKind.SYMLINK

    if stat.S_ISFIFO(mode):
        return EntryKind.FIFO

    if stat.S_ISSOCK(mode):
        return EntryKind.SOCKET

    if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        return EntryKind.DEVICE

    return EntryKind.OTHER


def _safe_relative(path: Path, root: Path) -> str:
    """Return a portable path relative to the scan root."""

    return path.relative_to(root).as_posix()


def _hash_fd(fd: int, chunk_bytes: int) -> str:
    """Calculate SHA-256 without loading the entire file into memory."""

    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)

    while True:
        chunk = os.read(fd, chunk_bytes)

        if not chunk:
            break

        digest.update(chunk)

    return digest.hexdigest()


def inventory_tree(
    root: Path,
    limits: ScanLimits,
) -> tuple[list[InventoryEntry], InventorySummary]:
    """Inventory a directory without following symlinks."""

    entries: list[InventoryEntry] = []
    summary = InventorySummary()

    # Each stack item contains a directory and its current depth.
    stack: list[tuple[Path, int]] = [(root, 0)]

    while stack:
        directory, depth = stack.pop()

        if depth > limits.max_depth:
            relative = (
                _safe_relative(directory, root)
                if directory != root
                else "."
            )

            entries.append(
                InventoryEntry(
                    relative_path=relative,
                    kind=EntryKind.DIRECTORY,
                    state=EntryState.LIMIT_EXCEEDED,
                    error=(
                        f"maximum recursion depth "
                        f"{limits.max_depth} exceeded"
                    ),
                )
            )

            summary.limit_exceeded += 1
            continue

        try:
            children = sorted(
                os.scandir(directory),
                key=lambda item: os.fsencode(item.name),
            )
        except OSError as exc:
            relative = (
                _safe_relative(directory, root)
                if directory != root
                else "."
            )

            entries.append(
                InventoryEntry(
                    relative_path=relative,
                    kind=EntryKind.DIRECTORY,
                    state=EntryState.ERROR,
                    error=(
                        "directory read failed: "
                        f"{exc.strerror or type(exc).__name__}"
                    ),
                )
            )

            summary.errors += 1
            continue

        child_directories: list[Path] = []

        for child in children:
            child_path = Path(child.path)
            relative = _safe_relative(child_path, root)

            try:
                info = child.stat(follow_symlinks=False)
            except OSError as exc:
                entries.append(
                    InventoryEntry(
                        relative_path=relative,
                        kind=EntryKind.OTHER,
                        state=EntryState.ERROR,
                        error=(
                            "lstat failed: "
                            f"{exc.strerror or type(exc).__name__}"
                        ),
                    )
                )

                summary.errors += 1
                continue

            kind = _entry_kind(info.st_mode)

            if kind == EntryKind.DIRECTORY:
                child_directories.append(child_path)
                continue

            # Symlinks, FIFOs, sockets, and devices are recorded,
            # but they are never opened or followed.
            if kind != EntryKind.REGULAR_FILE:
                entries.append(
                    InventoryEntry(
                        relative_path=relative,
                        kind=kind,
                        state=EntryState.SKIPPED,
                        mode=oct(stat.S_IMODE(info.st_mode)),
                        evidence=[
                            "special entry recorded but never followed or read"
                        ],
                    )
                )

                summary.skipped_entries += 1
                continue

            summary.regular_files += 1

            if summary.regular_files > limits.max_file_count:
                entries.append(
                    InventoryEntry(
                        relative_path=relative,
                        kind=kind,
                        state=EntryState.LIMIT_EXCEEDED,
                        size_bytes=info.st_size,
                        mode=oct(stat.S_IMODE(info.st_mode)),
                        error=(
                            f"maximum file count "
                            f"{limits.max_file_count} exceeded; "
                            "inventory stopped"
                        ),
                    )
                )

                summary.limit_exceeded += 1
                entries.sort(
                    key=lambda entry: os.fsencode(
                        entry.relative_path
                    )
                )
                return entries, summary

            try:
                fd, opened_info = open_regular_nofollow(
                    child_path
                )

                try:
                    summary.total_bytes += opened_info.st_size

                    limit_errors: list[str] = []

                    if (
                        opened_info.st_size
                        > limits.max_file_bytes
                    ):
                        limit_errors.append(
                            f"maximum individual size "
                            f"{limits.max_file_bytes} bytes exceeded"
                        )

                    total_exceeded = (
                        summary.total_bytes
                        > limits.max_total_bytes
                    )

                    if total_exceeded:
                        limit_errors.append(
                            f"maximum total size "
                            f"{limits.max_total_bytes} bytes exceeded; "
                            "inventory stopped"
                        )

                    if limit_errors:
                        entries.append(
                            InventoryEntry(
                                relative_path=relative,
                                kind=kind,
                                state=EntryState.LIMIT_EXCEEDED,
                                size_bytes=opened_info.st_size,
                                mode=oct(
                                    stat.S_IMODE(
                                        opened_info.st_mode
                                    )
                                ),
                                error="; ".join(limit_errors),
                            )
                        )

                        summary.limit_exceeded += 1

                        if total_exceeded:
                            entries.sort(
                                key=lambda entry: os.fsencode(
                                    entry.relative_path
                                )
                            )
                            return entries, summary

                        continue

                    type_result = detect_type(
                        fd,
                        opened_info.st_size,
                    )

                    sha256 = _hash_fd(
                        fd,
                        limits.hash_chunk_bytes,
                    )

                finally:
                    os.close(fd)

            except OSError as exc:
                entries.append(
                    InventoryEntry(
                        relative_path=relative,
                        kind=kind,
                        state=EntryState.ERROR,
                        size_bytes=info.st_size,
                        mode=oct(stat.S_IMODE(info.st_mode)),
                        error=(
                            "safe open/read failed: "
                            f"{exc.strerror or str(exc)}"
                        ),
                    )
                )

                summary.errors += 1
                continue

            evidence = filename_evidence(
                Path(relative),
                type_result.routing_class,
            )

            entries.append(
                InventoryEntry(
                    relative_path=relative,
                    kind=kind,
                    state=EntryState.INVENTORIED,
                    size_bytes=opened_info.st_size,
                    mode=oct(
                        stat.S_IMODE(opened_info.st_mode)
                    ),
                    sha256=sha256,
                    detected_type=type_result.description,
                    routing_class=type_result.routing_class,
                    evidence=evidence,
                )
            )

            summary.hashed_files += 1
            summary.review_flags += len(evidence)

            if type_result.routing_class in {
                RoutingClass.PE_EXECUTABLE,
                RoutingClass.PE_DLL,
                RoutingClass.ELF,
            }:
                summary.supported_binaries += 1

        # Reversing preserves sorted traversal with a LIFO stack.
        for child_directory in reversed(child_directories):
            stack.append((child_directory, depth + 1))

    entries.sort(
        key=lambda entry: os.fsencode(entry.relative_path)
    )

    return entries, summary