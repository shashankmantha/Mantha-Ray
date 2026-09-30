from __future__ import annotations

import subprocess
import tempfile
import unittest

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class SetupScriptTests(unittest.TestCase):
    def test_shell_scripts_have_valid_syntax(self) -> None:
        scripts = (
            PROJECT_ROOT
            / "scripts"
            / "check-requirements.sh",
            PROJECT_ROOT / "scripts" / "setup.sh",
            PROJECT_ROOT / "mantha-ray.sh",
        )

        for script in scripts:
            with self.subTest(script=script.name):
                result = subprocess.run(
                    ["bash", "-n", str(script)],
                    check=False,
                    capture_output=True,
                    text=True,
                )

                self.assertEqual(
                    result.returncode,
                    0,
                    result.stderr,
                )

    def test_launcher_explains_missing_setup(self) -> None:
        source = PROJECT_ROOT / "mantha-ray.sh"

        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            launcher = temporary_root / "mantha-ray.sh"
            launcher.write_text(
                source.read_text(encoding="utf-8"),
                encoding="utf-8",
            )

            result = subprocess.run(
                ["bash", str(launcher)],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "./scripts/setup.sh",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
