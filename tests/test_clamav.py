from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from static_triage.clamav import (
    ClamAVStatus,
    run_clamav,
)
from static_triage.runner import CommandResult


def command_result(
    return_code: int,
    *,
    stdout: str = "",
    stderr: str = "",
    timed_out: bool = False,
    output_truncated: bool = False,
) -> CommandResult:
    return CommandResult(
        command=("clamscan",),
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        output_truncated=output_truncated,
        duration_seconds=0.25,
    )


class ClamAVTests(unittest.TestCase):
    @patch("static_triage.clamav.run_command")
    def test_builds_safe_recursive_command(
        self,
        mocked_run,
    ) -> None:
        mocked_run.return_value = command_result(0)
        target = Path("/staging/sample")

        result = run_clamav(
            target,
            executable="/usr/bin/clamscan",
        )

        command = mocked_run.call_args.args[0]

        self.assertEqual(result.status, ClamAVStatus.CLEAN)
        self.assertIn("--recursive=yes", command)
        self.assertIn("--cross-fs=no", command)
        self.assertIn(
            "--follow-dir-symlinks=0",
            command,
        )
        self.assertIn(
            "--follow-file-symlinks=0",
            command,
        )
        self.assertEqual(command[-1], str(target))

        destructive_options = (
            "--remove",
            "--move",
            "--copy",
        )

        self.assertFalse(
            any(
                argument.startswith(destructive_options)
                for argument in command
            )
        )

    @patch("static_triage.clamav.run_command")
    def test_parses_infection(
        self,
        mocked_run,
    ) -> None:
        mocked_run.return_value = command_result(
            1,
            stdout=(
                "/staging/sample/eicar.com: "
                "Win.Test.EICAR_HDB-1 FOUND\n"
            ),
        )

        result = run_clamav(
            Path("/staging/sample")
        )

        self.assertEqual(
            result.status,
            ClamAVStatus.INFECTED,
        )
        self.assertTrue(result.complete)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(
            result.findings[0].relative_path,
            "eicar.com",
        )
        self.assertEqual(
            result.findings[0].signature,
            "Win.Test.EICAR_HDB-1",
        )

    @patch("static_triage.clamav.run_command")
    def test_normalizes_clean_scan(
        self,
        mocked_run,
    ) -> None:
        mocked_run.return_value = command_result(0)

        result = run_clamav(
            Path("/staging/sample")
        )

        self.assertEqual(
            result.status,
            ClamAVStatus.CLEAN,
        )
        self.assertTrue(result.complete)
        self.assertEqual(result.findings, ())

    @patch("static_triage.clamav.run_command")
    def test_normalizes_scanner_error(
        self,
        mocked_run,
    ) -> None:
        mocked_run.return_value = command_result(
            2,
            stderr="database initialization failed",
        )

        result = run_clamav(
            Path("/staging/sample")
        )

        self.assertEqual(
            result.status,
            ClamAVStatus.ERROR,
        )
        self.assertFalse(result.complete)
        self.assertIn("code 2", result.error or "")

    @patch("static_triage.clamav.run_command")
    def test_normalizes_timeout(
        self,
        mocked_run,
    ) -> None:
        mocked_run.return_value = command_result(
            -15,
            timed_out=True,
        )

        result = run_clamav(
            Path("/staging/sample")
        )

        self.assertEqual(
            result.status,
            ClamAVStatus.TIMED_OUT,
        )
        self.assertFalse(result.complete)


if __name__ == "__main__":
    unittest.main()