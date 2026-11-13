from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from static_triage.reference_check import (
    group_by_hash,
    load_reference,
    main,
    read_executables,
)

CASE = "case-20261110T031437Z-f9ad5f4e"


def digest(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()


def record(path: str, size: int, routing: str = "pe_dll", **changes) -> dict:
    return {
        "relative_path": path, "kind": "regular_file", "state": "inventoried",
        "sha256": digest(path), "size_bytes": size, "routing_class": routing,
        **changes,
    }


class ReadTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.results = Path(self._temporary.name)
        self.case = self.results / CASE
        self.case.mkdir()

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def write(self, lines: list) -> None:
        with (self.case / "files.jsonl").open("w") as handle:
            for line in lines:
                handle.write((json.dumps(line) if isinstance(line, dict) else line) + "\n")

    def test_only_analyzed_executables_are_listed(self) -> None:
        self.write([
            record("bin/Steam.dll", 2_900_000),
            record("game.exe", 3_200_000, "pe_executable"),
            record("bin/tool", 500_000, "elf"),
            record("tools/export.dle", 400_000),          # a DLL under an odd name
            record("data/level.pak", 50_000_000, "other"),  # not analyzed
            record("notes.txt", 500, "text"),
            record("bin/gone.dll", 100, state="error"),   # not inventoried
            record("dir", 0, "other", kind="directory"),
            "{not json",
            json.dumps({"relative_path": "x.dll", "kind": "regular_file",
                        "state": "inventoried", "routing_class": "pe_dll"}),  # no hash
        ])
        found = sorted(r.relative_path for r in read_executables(self.case))
        self.assertEqual(found, ["bin/Steam.dll", "bin/tool", "game.exe", "tools/export.dle"])

    def test_missing_file_is_not_an_error(self) -> None:
        self.assertEqual(read_executables(self.results / "nope"), [])

    def test_identical_copies_group_biggest_first(self) -> None:
        self.write([
            record("bin/SDL2.dll", 660_000),
            {**record("mods/SDL2.dll", 660_000), "sha256": digest("bin/SDL2.dll")},
            record("bin/Steam.dll", 2_900_000),
        ])
        groups = group_by_hash(read_executables(self.case))
        self.assertEqual([g.name for g in groups], ["bin/Steam.dll", "bin/SDL2.dll"])
        self.assertEqual([g.copies for g in groups], [0, 1])
        self.assertEqual(groups[1].paths, ("bin/SDL2.dll", "mods/SDL2.dll"))

    def test_output_and_matching(self) -> None:
        self.write([record("bin/steamclient.dll", 1_200_000), record("bin/other.dll", 900)])
        reference = self.results / "reference.jsonl"
        with reference.open("w") as handle:
            handle.write(json.dumps({
                "sha256": digest("bin/steamclient.dll").upper(),  # case is ignored
                "name": "steamclient.dll", "source": "Goldberg 0.2.5",
                "kind": "crack-component",
            }) + "\n")
            handle.write("\n{not json\n")
        self.assertEqual(len(load_reference(reference)), 1)

        import contextlib
        import io

        text = io.StringIO()
        with contextlib.redirect_stdout(text):
            main([str(self.case), "--check", str(reference)])
        output = text.getvalue()
        self.assertIn("Goldberg 0.2.5 (known crack component)", output)
        self.assertIn("1 of 2 unique executables matched", output)
        # Short hashes by default, whole ones on request.
        self.assertIn(digest("bin/steamclient.dll")[:12], output)
        self.assertNotIn(digest("bin/steamclient.dll"), output)
        text = io.StringIO()
        with contextlib.redirect_stdout(text):
            main([str(self.case), "--full"])
        self.assertIn(digest("bin/steamclient.dll"), text.getvalue())

    def test_a_results_folder_covers_every_case(self) -> None:
        self.write([record("bin/a.dll", 100)])
        other = self.results / "case-20261109T190532Z-e1cca4ac"
        other.mkdir()
        (other / "files.jsonl").write_text(json.dumps(record("bin/b.dll", 200)) + "\n")
        (self.results / "not-a-case").mkdir()
        import contextlib
        import io

        text = io.StringIO()
        with contextlib.redirect_stdout(text):
            main([str(self.results)])
        output = text.getvalue()
        self.assertIn("2 unique executables across 2 cases.", output)
        self.assertIn(CASE, output)
        self.assertIn("case-20261109T190532Z-e1cca4ac", output)


if __name__ == "__main__":
    unittest.main()
