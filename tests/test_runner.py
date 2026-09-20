from __future__ import annotations

import sys
import unittest

from static_triage.runner import run_command


class RunnerTests(unittest.TestCase):
    def test_captures_output_and_exit_code(self) -> None:
        result = run_command(
            [
                sys.executable,
                "-c",
                (
                    "import sys; "
                    "print('standard output'); "
                    "print('standard error', file=sys.stderr); "
                    "raise SystemExit(3)"
                ),
            ]
        )

        self.assertEqual(result.return_code, 3)
        self.assertIn("standard output", result.stdout)
        self.assertIn("standard error", result.stderr)
        self.assertFalse(result.timed_out)

    def test_times_out_command(self) -> None:
        result = run_command(
            [
                sys.executable,
                "-c",
                "import time; time.sleep(5)",
            ],
            timeout_seconds=0.1,
        )

        self.assertTrue(result.timed_out)
        self.assertLess(result.duration_seconds, 2.0)

    def test_truncates_excessive_output(self) -> None:
        result = run_command(
            [
                sys.executable,
                "-c",
                "import os; os.write(1, b'x' * 4096)",
            ],
            max_output_bytes=64,
        )

        self.assertEqual(len(result.stdout), 64)
        self.assertTrue(result.output_truncated)

    def test_does_not_invoke_a_shell(self) -> None:
        argument = "; echo injected"

        result = run_command(
            [
                sys.executable,
                "-c",
                "import sys; print(sys.argv[1])",
                argument,
            ]
        )

        self.assertEqual(
            result.stdout.strip(),
            argument,
        )


if __name__ == "__main__":
    unittest.main()