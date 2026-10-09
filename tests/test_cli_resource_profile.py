from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from static_triage.cli import (
    MAX_RESOURCE_PROFILE_CHARS,
    build_parser,
    main,
    resolve_scan_profile,
)
from static_triage.config import ScanLimits
from static_triage.resource_profiles import (
    ResourceProfileError,
    resolve_profile,
)


def _args(*extra: str):
    return build_parser().parse_args(
        [
            "scan",
            "sample",
            "--staging-root",
            "/staging",
            "--results-root",
            "/results",
            *extra,
        ]
    )


def _profile_arg(profile) -> str:
    return json.dumps(profile.to_dict())


class ScanProfileResolutionTests(unittest.TestCase):
    def test_no_profile_means_balanced_and_old_limits(self) -> None:
        profile = resolve_scan_profile(_args())
        self.assertEqual(profile.name, "balanced")
        self.assertEqual(profile.scan_limits(), ScanLimits())

    def test_host_profile_applied(self) -> None:
        sent = resolve_profile("high")
        profile = resolve_scan_profile(
            _args("--resource-profile", _profile_arg(sent))
        )
        self.assertEqual(profile, sent)
        limits = profile.scan_limits()
        self.assertEqual(limits.capa_total_timeout_seconds, 7200.0)
        self.assertEqual(limits.max_floss_files, 100)

    def test_custom_profile_applied(self) -> None:
        sent = resolve_profile(
            "balanced",
            {"capa_file_timeout_seconds": 150},
        )
        profile = resolve_scan_profile(
            _args("--resource-profile", _profile_arg(sent))
        )
        self.assertEqual(profile.scan_limits().capa_file_timeout_seconds, 150.0)

    def test_explicit_flags_override_profile(self) -> None:
        sent = resolve_profile("high")
        profile = resolve_scan_profile(
            _args(
                "--resource-profile",
                _profile_arg(sent),
                "--max-files",
                "100",
            )
        )
        self.assertTrue(profile.is_custom)
        self.assertEqual(profile.base, "high")
        self.assertEqual(profile.max_file_count, 100)
        self.assertEqual(profile.capa_total_timeout_seconds, 7200)

    def test_explicit_flags_without_profile(self) -> None:
        profile = resolve_scan_profile(_args("--max-depth", "8"))
        self.assertEqual(profile.max_depth, 8)
        self.assertEqual(profile.changed_fields(), {"max_depth": 8})

    def test_explicit_flags_are_bounds_checked(self) -> None:
        for flag, value in (("--max-files", "0"), ("--max-depth", "-1")):
            with self.subTest(flag=flag):
                with self.assertRaises(ResourceProfileError):
                    resolve_scan_profile(_args(flag, value))

    def test_untrusted_profile_rejected(self) -> None:
        tampered = resolve_profile("balanced").to_dict()
        tampered["values"]["memory_mib"] = 999_999
        cases = {
            "not json": "{nope",
            "too large": "x" * (MAX_RESOURCE_PROFILE_CHARS + 1),
            "array": "[]",
            "tampered": json.dumps(tampered),
            "extra key": json.dumps(
                {**resolve_profile().to_dict(), "privileged": True}
            ),
        }
        for label, raw in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(ResourceProfileError):
                    resolve_scan_profile(_args("--resource-profile", raw))

    def test_invalid_profile_fails_before_scanning(self) -> None:
        stderr = io.StringIO()
        with (
            patch("static_triage.cli.run_inventory_scan") as scan,
            contextlib.redirect_stderr(stderr),
        ):
            code = main(
                [
                    "scan",
                    "sample",
                    "--staging-root",
                    "/staging",
                    "--results-root",
                    "/results",
                    "--resource-profile",
                    "{nope",
                ]
            )
        self.assertEqual(code, 2)
        scan.assert_not_called()
        error = json.loads(stderr.getvalue())
        self.assertFalse(error["ok"])
        self.assertIn("Invalid resource profile", error["error"])

    def test_profile_limits_reach_the_scanner(self) -> None:
        sent = resolve_profile("constrained")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            with (
                patch("static_triage.cli.run_inventory_scan") as scan,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                scan.return_value.case_id = "case-x"
                scan.return_value.status = "clean"
                scan.return_value.case_directory = base
                scan.return_value.report_path = base / "report.md"
                code = main(
                    [
                        "scan",
                        "sample",
                        "--staging-root",
                        str(base),
                        "--results-root",
                        str(base),
                        "--resource-profile",
                        _profile_arg(sent),
                    ]
                )
        self.assertEqual(code, 0)
        config = scan.call_args.args[1]
        self.assertEqual(config.limits, sent.scan_limits())


if __name__ == "__main__":
    unittest.main()