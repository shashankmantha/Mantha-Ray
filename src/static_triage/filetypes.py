"""Content-based file detection and filename review checks."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .models import RoutingClass


@dataclass(frozen=True, slots=True)
class TypeResult:
    """Result returned by content-based file detection."""

    description: str
    routing_class: RoutingClass


def _read_at(fd: int, offset: int, size: int) -> bytes:
    """Read bytes at an offset without changing the file position."""

    if hasattr(os, "pread"):
        return os.pread(fd, size, offset)

    os.lseek(fd, offset, os.SEEK_SET)
    return os.read(fd, size)


def detect_type(fd: int, size_bytes: int) -> TypeResult:
    """Identify a file's general type using its contents."""

    if size_bytes == 0:
        return TypeResult("empty file", RoutingClass.EMPTY)

    head = _read_at(fd, 0, min(size_bytes, 8192))

    # Windows PE executable or DLL
    if head.startswith(b"MZ") and size_bytes >= 64:
        pe_offset = int.from_bytes(head[0x3C:0x40], "little")

        if pe_offset <= size_bytes - 24:
            signature_and_coff = _read_at(fd, pe_offset, 24)
        else:
            signature_and_coff = b""

        if signature_and_coff.startswith(b"PE\x00\x00"):
            characteristics = int.from_bytes(
                signature_and_coff[22:24],
                "little",
            )

            if characteristics & 0x2000:
                return TypeResult("PE DLL", RoutingClass.PE_DLL)

            return TypeResult(
                "PE executable",
                RoutingClass.PE_EXECUTABLE,
            )

        return TypeResult(
            "DOS MZ executable or malformed PE",
            RoutingClass.OTHER,
        )

    # Linux executable or shared library
    if head.startswith(b"\x7fELF"):
        elf_class = head[4] if len(head) > 4 else 0
        bits = {
            1: "32-bit",
            2: "64-bit",
        }.get(elf_class, "unknown class")

        return TypeResult(f"ELF {bits}", RoutingClass.ELF)

    signatures = (
        (b"PK\x03\x04", "ZIP archive", RoutingClass.ARCHIVE),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", RoutingClass.ARCHIVE),
        (b"Rar!\x1a\x07", "RAR archive", RoutingClass.ARCHIVE),
        (b"\x1f\x8b", "gzip archive", RoutingClass.ARCHIVE),
        (b"%PDF-", "PDF document", RoutingClass.DOCUMENT),
        (b"\x89PNG\r\n\x1a\n", "PNG image", RoutingClass.MEDIA),
        (b"\xff\xd8\xff", "JPEG image", RoutingClass.MEDIA),
        (b"GIF87a", "GIF image", RoutingClass.MEDIA),
        (b"GIF89a", "GIF image", RoutingClass.MEDIA),
    )

    for signature, description, route in signatures:
        if head.startswith(signature):
            return TypeResult(description, route)

    # Shell, Python, or other shebang-based script
    if head.startswith(b"#!"):
        first_line = head.splitlines()[0][:160]
        interpreter = first_line.decode("utf-8", "replace")

        return TypeResult(
            f"script ({interpreter})",
            RoutingClass.SCRIPT,
        )

    # Basic text detection
    sample = head[:4096]

    if sample and b"\x00" not in sample:
        try:
            sample.decode("utf-8")
            return TypeResult("UTF-8 text", RoutingClass.TEXT)
        except UnicodeDecodeError:
            pass

    return TypeResult(
        "unrecognized binary data",
        RoutingClass.OTHER,
    )


_EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".com",
    ".cpl",
    ".sys",
}

_SCRIPT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".sh",
    ".py",
}

_ARCHIVE_EXTENSIONS = {
    ".zip",
    ".7z",
    ".rar",
    ".gz",
    ".tar",
}

_DOCUMENT_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
}

_MEDIA_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".mp3",
    ".mp4",
}

_TEXT_EXTENSIONS = {
    ".txt",
    ".md",
    ".toml",
    ".json",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".log",
    ".csv",
}

def filename_evidence(
    path: Path,
    route: RoutingClass,
) -> list[str]:
    """Return review evidence for suspicious filenames."""

    suffixes = [
        suffix.lower()
        for suffix in path.suffixes
    ]

    final_suffix = suffixes[-1] if suffixes else ""
    evidence: list[str] = []

    route_extensions = {
        RoutingClass.PE_EXECUTABLE: _EXECUTABLE_EXTENSIONS,
        RoutingClass.PE_DLL: _EXECUTABLE_EXTENSIONS,
        RoutingClass.SCRIPT: _SCRIPT_EXTENSIONS,
        RoutingClass.ARCHIVE: _ARCHIVE_EXTENSIONS,
        RoutingClass.DOCUMENT: _DOCUMENT_EXTENSIONS,
        RoutingClass.MEDIA: _MEDIA_EXTENSIONS,
        RoutingClass.TEXT: _TEXT_EXTENSIONS,
    }

    expected_extensions = route_extensions.get(route)

    known_extensions = set().union(
        _EXECUTABLE_EXTENSIONS,
        _SCRIPT_EXTENSIONS,
        _ARCHIVE_EXTENSIONS,
        _DOCUMENT_EXTENSIONS,
        _MEDIA_EXTENSIONS,
        _TEXT_EXTENSIONS,
    )

    if (
        expected_extensions
        and final_suffix
        and final_suffix not in expected_extensions
    ):
        evidence.append(
            f"extension/type mismatch: "
            f"{final_suffix} vs {route.value}"
        )

    elif (
        final_suffix in known_extensions
        and expected_extensions is None
    ):
        evidence.append(
            f"extension/type mismatch: "
            f"{final_suffix} vs {route.value}"
        )

    dangerous_extensions = (
        _EXECUTABLE_EXTENSIONS | _SCRIPT_EXTENSIONS
    )

    decoy_extensions = (
        _DOCUMENT_EXTENSIONS
        | _MEDIA_EXTENSIONS
        | _ARCHIVE_EXTENSIONS
        | _TEXT_EXTENSIONS
    )

    if (
        len(suffixes) >= 2
        and suffixes[-1] in dangerous_extensions
        and suffixes[-2] in decoy_extensions
    ):
        evidence.append("double-extension filename")

    return evidence


def open_regular_nofollow(
    path: Path,
) -> tuple[int, os.stat_result]:
    """Open a regular file without following a final symlink."""

    flags = os.O_RDONLY

    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(path, flags)
    info = os.fstat(fd)

    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise OSError(
            "entry changed and is no longer a regular file"
        )

    return fd, info