from __future__ import annotations

import mmap
import re
from dataclasses import dataclass
from pathlib import Path

# Readable runs, as FLOSS's static pass finds them: ASCII, and UTF-16LE.
MIN_LENGTH = 6
_ASCII = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LENGTH)
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_LENGTH)

# Large files are read up to this many bytes; the rest is reported as not
# scanned rather than silently skipped.
MAX_SCAN_BYTES = 512 * 1024**2
MAX_MATCHES = 200
MAX_STRING_CHARS = 512

# Strings worth a human's attention in a big binary. Kept deliberately
# specific: generic patterns (any base58 run, any hex blob) would flood the
# list with noise from compiled code and data. These move into the
# core-threats pack once YARA-X is in place.
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("url", re.compile(r"(?:https?|ftp)://[^\s\"'<>]{4,}", re.I)),
    ("miner pool", re.compile(r"stratum\+(?:tcp|ssl|tls)://", re.I)),
    # Only with a port: bare dotted numbers are mostly version strings.
    (
        "ip address and port",
        re.compile(
            r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1?\d?\d):\d{2,5}(?![\d.])"
        ),
    ),
    ("onion address", re.compile(r"\b[a-z2-7]{56}\.onion\b", re.I)),
    (
        "command",
        re.compile(
            r"\b(?:powershell(?:\.exe)?\s+-\w|cmd(?:\.exe)?\s+/[ck]\b|"
            r"schtasks(?:\.exe)?\s+/create|reg(?:\.exe)?\s+add\b|"
            r"rundll32(?:\.exe)?\s|regsvr32(?:\.exe)?\s|mshta(?:\.exe)?\s|"
            r"certutil(?:\.exe)?\s+-urlcache|bitsadmin(?:\.exe)?\s+/transfer|"
            r"vssadmin(?:\.exe)?\s+delete|bcdedit(?:\.exe)?\s+/set|"
            r"wmic(?:\.exe)?\s+shadowcopy)",
            re.I,
        ),
    ),
    (
        "defence change",
        re.compile(
            r"\b(?:Add-MpPreference|Set-MpPreference|"
            r"DisableRealtimeMonitoring|ExclusionPath)\b",
            re.I,
        ),
    ),
    (
        "autostart",
        re.compile(
            r"\\CurrentVersion\\(?:Run|RunOnce|Policies\\Explorer\\Run)\b|"
            r"\\Start Menu\\Programs\\Startup\b",
            re.I,
        ),
    ),
    (
        "credential store",
        re.compile(
            r"\\(?:Login Data|Local State|Cookies|Web Data)\b|"
            r"\\(?:discord|discordcanary|discordptb)\\Local Storage|"
            r"\\Telegram Desktop\\tdata|\bwallet\.dat\b|"
            r"\\(?:Exodus|Electrum|Atomic|Ethereum)\\",
            re.I,
        ),
    ),
    (
        "crypto address",
        re.compile(
            r"\b(?:bc1[ac-hj-np-z02-9]{39,59}|0x[a-fA-F0-9]{40}|"
            r"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b"
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class PlainMatch:
    category: str
    value: str
    encoding: str
    truncated: bool


@dataclass(frozen=True, slots=True)
class PlainResult:
    matches: tuple[PlainMatch, ...]
    total_strings: int
    scanned_bytes: int
    file_bytes: int
    matches_truncated: bool

    @property
    def fully_scanned(self) -> bool:
        return self.scanned_bytes >= self.file_bytes


def _category(text: str) -> str | None:
    for category, pattern in PATTERNS:
        if pattern.search(text):
            return category
    return None


def extract(
    path: Path,
    *,
    max_scan_bytes: int = MAX_SCAN_BYTES,
    max_matches: int = MAX_MATCHES,
    max_chars: int = MAX_STRING_CHARS,
) -> PlainResult:
    with path.open("rb") as handle:
        file_bytes = handle.seek(0, 2)
        if file_bytes == 0:
            return PlainResult((), 0, 0, 0, False)
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            view = memoryview(data)[: min(file_bytes, max_scan_bytes)]
            try:
                seen: set[str] = set()
                matches: list[PlainMatch] = []
                total = 0
                capped = False
                for encoding, pattern in (("ASCII", _ASCII), ("UTF-16LE", _UTF16)):
                    for found in pattern.finditer(view):
                        total += 1
                        raw = found.group()
                        text = (
                            raw.decode("ascii")
                            if encoding == "ASCII"
                            else raw.decode("utf-16-le")
                        )
                        category = _category(text)
                        if category is None or text in seen:
                            continue
                        if len(matches) >= max_matches:
                            capped = True
                            continue
                        seen.add(text)
                        clipped = len(text) > max_chars
                        matches.append(
                            PlainMatch(
                                category=category,
                                value=(text[: max_chars - 1] + "…") if clipped else text,
                                encoding=encoding,
                                truncated=clipped,
                            )
                        )
                return PlainResult(
                    matches=tuple(matches),
                    total_strings=total,
                    scanned_bytes=len(view),
                    file_bytes=file_bytes,
                    matches_truncated=capped,
                )
            finally:
                view.release()