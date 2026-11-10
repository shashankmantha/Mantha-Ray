from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from static_triage.filetypes import detect_type, filename_evidence
from static_triage.models import RoutingClass


def detect(data: bytes) -> tuple[str, RoutingClass]:
    with tempfile.NamedTemporaryFile() as handle:
        handle.write(data)
        handle.flush()
        fd = os.open(handle.name, os.O_RDONLY)
        try:
            result = detect_type(fd, len(data))
        finally:
            os.close(fd)
    return result.description, result.routing_class


def mismatch(name: str, route: RoutingClass) -> bool:
    return any("extension/type mismatch" in item for item in filename_evidence(Path(name), route))


class DetectTests(unittest.TestCase):
    def test_media_formats(self) -> None:
        cases = {
            b"ID3\x04\x00\x00\x00\x00\x00\x00" + b"\x00" * 64: "MP3 audio",
            # An MP3 with no ID3 tag: MPEG-1 Layer III, 128 kbit/s, 44.1 kHz.
            b"\xff\xfb\x90\x64" + b"\x00" * 64: "MPEG audio (MP3)",
            b"OggS\x00\x02" + b"\x00" * 64: "Ogg audio/video",
            b"fLaC\x00\x00\x00\x22" + b"\x00" * 64: "FLAC audio",
            b"RIFF\x24\x08\x00\x00WAVEfmt " + b"\x00" * 64: "WAV audio",
            b"RIFF\x24\x08\x00\x00WEBPVP8 " + b"\x00" * 64: "WebP image",
            b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 64: "MP4/QuickTime media",
            b"DDS \x7c\x00\x00\x00" + b"\x00" * 64: "DDS texture",
        }
        for data, description in cases.items():
            with self.subTest(description=description):
                self.assertEqual(detect(data), (description, RoutingClass.MEDIA))

    def test_lookalikes_are_not_media(self) -> None:
        self.assertEqual(detect(b"\xff\xd8\xff\xe0" + b"\x00" * 64)[0], "JPEG image")
        # Reserved MPEG version and layer bits aren't an MP3 frame.
        self.assertEqual(detect(b"\xff\xe9\x90\x64" + b"\x00" * 64)[1], RoutingClass.OTHER)
        self.assertEqual(detect(b"\xff\xf9\xf0\x64" + b"\x00" * 64)[1], RoutingClass.OTHER)
        self.assertEqual(detect(b"RIFF\x24\x08\x00\x00XXXX" + b"\x00" * 64)[1], RoutingClass.OTHER)

    def test_utf16_text(self) -> None:
        self.assertEqual(detect("﻿[Settings]\r\nvolume=5\r\n".encode("utf-16-le")),
                         ("UTF-16 text", RoutingClass.TEXT))
        self.assertEqual(detect("﻿hello".encode("utf-16-be")), ("UTF-16 text", RoutingClass.TEXT))


class MismatchTests(unittest.TestCase):
    def test_text_with_any_text_extension_is_fine(self) -> None:
        for name in ("animations.xml", "main.lua", "unit.shader", "readme", "notes.TXT", "build.py"):
            with self.subTest(name=name):
                self.assertFalse(mismatch(name, RoutingClass.TEXT))

    def test_text_claiming_a_binary_format_is_flagged(self) -> None:
        for name in ("setup.exe", "photo.jpg", "song.mp3", "data.zip", "report.pdf"):
            with self.subTest(name=name):
                self.assertTrue(mismatch(name, RoutingClass.TEXT))

    def test_zip_based_formats(self) -> None:
        for name in ("report.docx", "mod.jar", "maps.pk3", "files.zip"):
            with self.subTest(name=name):
                self.assertFalse(mismatch(name, RoutingClass.ARCHIVE))
        self.assertTrue(mismatch("invoice.pdf", RoutingClass.ARCHIVE))

    def test_other_mismatches_still_flagged(self) -> None:
        self.assertTrue(mismatch("song.mp3", RoutingClass.PE_EXECUTABLE))
        self.assertTrue(mismatch("song.mp3", RoutingClass.OTHER))
        self.assertFalse(mismatch("song.mp3", RoutingClass.MEDIA))
        self.assertFalse(mismatch("music.ogg", RoutingClass.MEDIA))


if __name__ == "__main__":
    unittest.main()
