from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from static_triage.plain_strings import _category, extract


def write(directory: str, data: bytes) -> Path:
    path = Path(directory) / "sample.bin"
    path.write_bytes(data)
    return path


class CategoryTests(unittest.TestCase):
    def test_kept(self) -> None:
        cases = {
            "connect 45.33.12.9:4444 now": "ip address and port",
            "http://1.2.3.4/x": "url",
            "stratum+ssl://pool:443": "miner pool",
            "cmd.exe /c del /q x": "command",
            "powershell -enc AAAA": "command",
            "schtasks /create /tn x": "command",
            "Add-MpPreference -ExclusionPath C:\\": "defence change",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run": "autostart",
            "AppData\\Roaming\\discord\\Local Storage\\leveldb": "credential store",
            "Google\\Chrome\\User Data\\Default\\Login Data": "credential store",
            "0x52908400098527886E0F7030069857D2E4169EE7": "crypto address",
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion": "onion address",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(_category(text), expected)

    def test_noise_ignored(self) -> None:
        for text in (
            "version 1.2.3.4",
            "255.255.255.255",
            "GetProcAddress",
            "This program cannot be run in DOS mode.",
            "hello world",
        ):
            with self.subTest(text=text):
                self.assertIsNone(_category(text))


class ExtractTests(unittest.TestCase):
    def test_ascii_and_utf16(self) -> None:
        data = (
            b"\x00\x01junk\x00"
            + b"stratum+tcp://pool.example.invalid:3333\x00\x01\x01"
            + "reg add HKCU\\x".encode("utf-16-le")
            + b"\x00\x00GetProcAddress\x00"
        )
        with tempfile.TemporaryDirectory() as temporary:
            result = extract(write(temporary, data))
        found = {(m.category, m.encoding) for m in result.matches}
        self.assertEqual(found, {("miner pool", "ASCII"), ("command", "UTF-16LE")})
        self.assertGreaterEqual(result.total_strings, 3)
        self.assertTrue(result.fully_scanned)

    def test_duplicates_kept_once(self) -> None:
        data = b"\x00".join([b"http://example.invalid/a"] * 5)
        with tempfile.TemporaryDirectory() as temporary:
            result = extract(write(temporary, data))
        self.assertEqual(len(result.matches), 1)

    def test_match_cap(self) -> None:
        data = b"\x00".join(
            f"http://example.invalid/{i}".encode() for i in range(20)
        )
        with tempfile.TemporaryDirectory() as temporary:
            result = extract(write(temporary, data), max_matches=5)
        self.assertEqual(len(result.matches), 5)
        self.assertTrue(result.matches_truncated)

    def test_scan_limit_is_reported(self) -> None:
        data = b"\x00" * 4096 + b"http://late.example.invalid/x"
        with tempfile.TemporaryDirectory() as temporary:
            result = extract(write(temporary, data), max_scan_bytes=1024)
        self.assertFalse(result.fully_scanned)
        self.assertEqual(result.matches, ())
        self.assertEqual(result.scanned_bytes, 1024)

    def test_long_strings_clipped(self) -> None:
        data = b"http://example.invalid/" + b"a" * 2000
        with tempfile.TemporaryDirectory() as temporary:
            result = extract(write(temporary, data), max_chars=64)
        self.assertEqual(len(result.matches[0].value), 64)
        self.assertTrue(result.matches[0].truncated)

    def test_empty_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = extract(write(temporary, b""))
        self.assertEqual(result.total_strings, 0)
        self.assertTrue(result.fully_scanned)


if __name__ == "__main__":
    unittest.main()