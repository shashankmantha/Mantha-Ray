from __future__ import annotations

import unittest
from unittest.mock import patch

from static_triage.preflight import inspect_tools
from static_triage.runner import CommandResult


def command_result(
    command: list[str],
    *,
    return_code: int = 0,
    stdout: str = "",
    stderr: str = "",
    timed_out: bool = False,
) -> CommandResult:
    return CommandResult(
        command=tuple(command),
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        output_truncated=False,
        duration_seconds=0.1,
    )


class PreflightTests(unittest.TestCase):
    @patch("static_triage.preflight.run_command")
    @patch("static_triage.preflight.shutil.which")
    def test_records_missing_tools(
        self,
        mocked_which,
        mocked_run,
    ) -> None:
        mocked_which.return_value = None

        tools = inspect_tools()

        self.assertEqual(len(tools), 3)
        self.assertTrue(
            all(not tool.available for tool in tools)
        )
        self.assertTrue(
            all(
                tool.error == "not found on PATH"
                for tool in tools
            )
        )
        mocked_run.assert_not_called()

    @patch("static_triage.preflight.run_command")
    @patch("static_triage.preflight.shutil.which")
    def test_records_available_tools(
        self,
        mocked_which,
        mocked_run,
    ) -> None:
        mocked_which.side_effect = (
            lambda name: f"/usr/bin/{name}"
        )

        def fake_run(
            command: list[str],
            **_: object,
        ) -> CommandResult:
            return command_result(
                command,
                stdout=f"{command[0]} version 1.0\n",
            )

        mocked_run.side_effect = fake_run

        tools = inspect_tools()

        self.assertEqual(len(tools), 3)
        self.assertTrue(
            all(tool.available for tool in tools)
        )
        self.assertTrue(
            all(tool.version for tool in tools)
        )

    @patch("static_triage.preflight.run_command")
    @patch("static_triage.preflight.shutil.which")
    def test_records_version_timeout(
        self,
        mocked_which,
        mocked_run,
    ) -> None:
        mocked_which.side_effect = (
            lambda name: f"/usr/bin/{name}"
        )

        mocked_run.side_effect = (
            lambda command, **_: command_result(
                command,
                return_code=-15,
                timed_out=True,
            )
        )

        tools = inspect_tools()

        self.assertTrue(
            all(not tool.available for tool in tools)
        )
        self.assertTrue(
            all(
                tool.error == "version check timed out"
                for tool in tools
            )
        )


if __name__ == "__main__":
    unittest.main()