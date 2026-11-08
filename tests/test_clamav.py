from __future__ import annotations

import hashlib
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from static_triage import clamav
from static_triage.clamav import (
    ClamAVStatus,
    run_clamav,
    scan_timeout_seconds,
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


    @patch("static_triage.clamav.run_command")
    def test_raises_limits_and_alerts_on_them(self, mocked_run) -> None:
        mocked_run.return_value = command_result(0)
        run_clamav(Path("/staging/sample"), timeout_seconds=1234.0)
        command = mocked_run.call_args.args[0]
        for flag in ("--alert-exceeds-max=yes", "--max-filesize=2047M",
                     "--max-scansize=2047M", "--max-scantime=600000"):
            self.assertIn(flag, command)
        self.assertEqual(mocked_run.call_args.kwargs["timeout_seconds"], 1234.0)

    @patch("static_triage.clamav.run_command")
    def test_limit_alerts_are_gaps_not_detections(self, mocked_run) -> None:
        mocked_run.return_value = command_result(1, stdout=(
            "/staging/sample/data/pak0.bin: Heuristics.Limits.Exceeded.MaxFileSize FOUND\n"
            "/staging/sample/movie.zip: Heuristics.Limits.Exceeded.MaxScanTime FOUND\n"
        ))
        result = run_clamav(Path("/staging/sample"), timeout_seconds=900.0)
        self.assertEqual(result.status, ClamAVStatus.CLEAN)
        self.assertFalse(result.complete)
        self.assertEqual(result.findings, ())
        self.assertEqual(
            [(hit.relative_path, hit.limit) for hit in result.limits_exceeded],
            [("data/pak0.bin", "MaxFileSize"), ("movie.zip", "MaxScanTime")],
        )
        self.assertIn("2 files were not fully scanned", result.error)
        payload = result.to_dict()
        self.assertEqual(payload["limits_exceeded"][0]["reason"],
                         "larger than ClamAV can scan (2047 MiB)")
        self.assertEqual(payload["limits"]["timeout_seconds"], 900.0)

    @patch("static_triage.clamav.run_command")
    def test_detection_beside_limit_alert_is_still_infected(self, mocked_run) -> None:
        mocked_run.return_value = command_result(1, stdout=(
            "/staging/sample/a.exe: Win.Trojan.Agent-1 FOUND\n"
            "/staging/sample/big.bin: Heuristics.Limits.Exceeded.MaxFileSize FOUND\n"
        ))
        result = run_clamav(Path("/staging/sample"))
        self.assertEqual(result.status, ClamAVStatus.INFECTED)
        self.assertEqual([f.signature for f in result.findings], ["Win.Trojan.Agent-1"])
        self.assertEqual(len(result.limits_exceeded), 1)
        self.assertFalse(result.complete)

    def test_timeout_scales_with_size(self) -> None:
        self.assertEqual(scan_timeout_seconds(None), 900.0)
        self.assertEqual(scan_timeout_seconds(0), 900.0)
        self.assertEqual(scan_timeout_seconds(10 * 1024**3), 900.0 + 1800.0)
        self.assertEqual(scan_timeout_seconds(10**15), 4 * 3600.0)


@unittest.skipUnless(shutil.which("clamscan"), "clamscan is not installed")
class RealClamscanTests(unittest.TestCase):
    """Runs the real clamscan against a one-signature database."""

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        root = Path(self._temporary.name)
        self.sample = root / "sample"
        self.sample.mkdir()
        hit = b"MANTHA-RAY-TEST-SIGNATURE"
        (self.sample / "hit.bin").write_bytes(hit)
        (self.sample / "big.bin").write_bytes(b"\0" * (2 * 1024 * 1024))
        (self.sample / "ok.txt").write_text("fine")
        database = root / "test.hdb"
        database.write_text(f"{hashlib.md5(hit).hexdigest()}:{len(hit)}:Mantha.Test.Sig-1\n")
        # The CVD age check refuses a database that isn't a signed CVD, so the
        # wrapper drops it and points clamscan at the test signature instead.
        self.wrapper = root / "clamscan"
        self.wrapper.write_text(
            "#!/bin/sh\n"
            "for a; do shift; case $a in --fail-if-cvd-older-than=*) ;; *) set -- \"$@\" \"$a\";; esac; done\n"
            f'exec {shutil.which("clamscan")} -d {database} "$@"\n'
        )
        self.wrapper.chmod(self.wrapper.stat().st_mode | stat.S_IXUSR)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_detection_and_size_limit(self) -> None:
        with patch.object(clamav, "MAX_FILE_MIB", 1):
            result = run_clamav(self.sample, executable=str(self.wrapper), timeout_seconds=120)
        self.assertEqual(result.status, ClamAVStatus.INFECTED, result.stderr)
        self.assertEqual([(f.relative_path, f.signature) for f in result.findings],
                         [("hit.bin", "Mantha.Test.Sig-1.UNOFFICIAL")])
        self.assertEqual([(h.relative_path, h.limit) for h in result.limits_exceeded],
                         [("big.bin", "MaxFileSize")])
        self.assertFalse(result.complete)

    def test_everything_under_the_limit_is_complete(self) -> None:
        (self.sample / "hit.bin").unlink()
        result = run_clamav(self.sample, executable=str(self.wrapper), timeout_seconds=120)
        self.assertEqual(result.status, ClamAVStatus.CLEAN, result.stderr)
        self.assertTrue(result.complete)
        self.assertEqual(result.limits_exceeded, ())


if __name__ == "__main__":
    unittest.main()