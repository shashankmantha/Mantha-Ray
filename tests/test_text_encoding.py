from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# UTF-8 text decoded as Windows-1252 and saved again: "—" becomes "â€”".
MOJIBAKE = ("â€", "Ã©", "Â ")


class EncodingTests(unittest.TestCase):
    def test_sources_have_no_double_encoded_text(self) -> None:
        files = [
            *ROOT.joinpath("src/static_triage").rglob("*.py"),
            *ROOT.joinpath("frontend/src").rglob("*.ts"),
            ROOT / "frontend/index.html",
            ROOT / "README.md",
        ]
        for path in files:
            text = path.read_text(encoding="utf-8")
            for marker in MOJIBAKE:
                with self.subTest(path=path.relative_to(ROOT).as_posix(), marker=marker):
                    self.assertNotIn(marker, text)


if __name__ == "__main__":
    unittest.main()