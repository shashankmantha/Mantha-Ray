from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from static_triage.host_scan import (
    DockerScanController,
    DockerScanRequest,
    HostScanError,
    build_docker_command,
    validate_request,
)
from static_triage.resource_profiles import resolve_profile

GIB = 1024**3


def _request(base: Path, profile=None) -> DockerScanRequest:
    source = base / "source"
    results = base / "results"
    source.mkdir(exist_ok=True)
    results.mkdir(exist_ok=True)
    kwargs = {} if profile is None else {"resource_profile": profile}
    return validate_request(DockerScanRequest(source, results, **kwargs))


def _command(request: DockerScanRequest) -> list[str]:
    with (
        patch("static_triage.container.command.os.getuid", return_value=1000),
        patch("static_triage.container.command.os.getgid", return_value=1000),
    ):
        return build_docker_command(request, "/usr/bin/docker", "NAME")


def _flag(command: list[str], name: str) -> str:
    return command[command.index(name) + 1]


class DockerCommandProfileTests(unittest.TestCase):
    def test_default_request_reproduces_pre_profile_command(self) -> None:
        # The exact command used before resource profiles existed.
        # Balanced must never drift from it.
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            command = _command(_request(base))
        self.assertEqual(
            command,
            [
                "/usr/bin/docker", "run", "--rm", "--name", "NAME",
                "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true",
                "--security-opt", "label=disable",
                "--pids-limit", "256", "--memory", "4g", "--cpus", "2",
                "--user", "1000:1000",
                "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777",
                "--mount",
                f"type=bind,source={base / 'source'},"
                "target=/staging/input,readonly",
                "--mount",
                f"type=bind,source={base / 'results'},target=/results",
                "static-triage:core", "scan", "input",
                "--staging-root", "/staging",
                "--results-root", "/results",
                "--progress-jsonl",
            ],
        )

    def test_default_host_timeout_is_four_hours(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            request = _request(Path(temporary))
        self.assertEqual(request.timeout_seconds, 4 * 60 * 60)
        self.assertEqual(request.resource_profile.name, "balanced")

    def test_presets_set_container_envelope(self) -> None:
        expected = {
            "constrained": ("128", "2g", "1", "size=256m", 2 * 3600),
            "balanced": ("256", "4g", "2", "size=512m", 4 * 3600),
            "high": ("512", "8g", "4", "size=1024m", 6 * 3600),
        }
        for name, (pids, memory, cpus, tmp, timeout) in expected.items():
            with self.subTest(preset=name):
                with tempfile.TemporaryDirectory() as temporary:
                    request = _request(
                        Path(temporary),
                        resolve_profile(name),
                    )
                    command = _command(request)
                self.assertEqual(_flag(command, "--pids-limit"), pids)
                self.assertEqual(_flag(command, "--memory"), memory)
                self.assertEqual(_flag(command, "--cpus"), cpus)
                self.assertIn(tmp, _flag(command, "--tmpfs"))
                self.assertEqual(request.timeout_seconds, timeout)

    def test_custom_values_formatted_for_docker(self) -> None:
        profile = resolve_profile(
            "balanced",
            {"cpus": 1.5, "memory_mib": 3000, "tmp_mib": 300},
        )
        with tempfile.TemporaryDirectory() as temporary:
            command = _command(_request(Path(temporary), profile))
        self.assertEqual(_flag(command, "--cpus"), "1.5")
        self.assertEqual(_flag(command, "--memory"), "3000m")
        self.assertIn("size=300m,", _flag(command, "--tmpfs"))

    def test_hardening_identical_across_profiles(self) -> None:
        hardening = [
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--security-opt", "label=disable",
        ]
        for profile in (
            resolve_profile("constrained"),
            resolve_profile("high"),
            resolve_profile("high", {"cpus": 64, "memory_mib": 262_144,
                                     "pids_limit": 4096}),
        ):
            with self.subTest(profile=profile.name):
                with tempfile.TemporaryDirectory() as temporary:
                    command = _command(_request(Path(temporary), profile))
                self.assertEqual(command[5:5 + len(hardening)], hardening)
                self.assertIn("noexec,nosuid,nodev", _flag(command, "--tmpfs"))
                self.assertIn("readonly", command[command.index("--mount") + 1])

    def test_request_without_profile_object_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / "s").mkdir()
            (base / "r").mkdir()
            with self.assertRaises(HostScanError):
                validate_request(
                    DockerScanRequest(
                        base / "s",
                        base / "r",
                        resource_profile={"cpus": 99},  # type: ignore[arg-type]
                    )
                )


class CapacityCheckTests(unittest.TestCase):
    def _controller_with_info(self, *, stdout="", returncode=0, exc=None):
        controller = DockerScanController(engine="docker")

        def fake_run(*args, **kwargs):
            if exc is not None:
                raise exc
            return subprocess.CompletedProcess(
                args[0], returncode, stdout=stdout, stderr=""
            )

        return controller, patch(
            "static_triage.container.controller.subprocess.run",
            side_effect=fake_run,
        )

    def _resolve(self):
        return patch.object(
            DockerScanController,
            "_resolve_engine",
            return_value="/usr/bin/docker",
        )

    def test_capacity_parsed_from_docker_info(self) -> None:
        controller, run = self._controller_with_info(
            stdout=f"8 {16 * GIB}\n"
        )
        with run, self._resolve():
            self.assertEqual(controller.docker_capacity(), (8.0, 16 * GIB))
            self.assertEqual(
                controller.check_resources(resolve_profile("balanced")),
                [],
            )

    def test_profile_larger_than_docker_rejected(self) -> None:
        controller, run = self._controller_with_info(
            stdout=f"2 {6 * GIB}\n"
        )
        with run, self._resolve():
            with self.assertRaisesRegex(HostScanError, "CPUs"):
                controller.check_resources(resolve_profile("high"))

    def test_large_memory_share_warns(self) -> None:
        controller, run = self._controller_with_info(
            stdout=f"8 {5 * GIB}\n"
        )
        with run, self._resolve():
            warnings = controller.check_resources(
                resolve_profile("balanced")
            )
        self.assertEqual(len(warnings), 1)

    def test_unreadable_capacity_warns_instead_of_blocking(self) -> None:
        cases = {
            "failed": {"returncode": 1},
            "garbage": {"stdout": "lots of memory"},
            "empty": {"stdout": ""},
            "negative": {"stdout": "-1 100"},
            "timeout": {"exc": subprocess.TimeoutExpired("docker", 15)},
            "missing": {"exc": OSError("gone")},
        }
        for label, kwargs in cases.items():
            with self.subTest(case=label):
                controller, run = self._controller_with_info(**kwargs)
                with run, self._resolve():
                    self.assertIsNone(controller.docker_capacity())
                    warnings = controller.check_resources(
                        resolve_profile("high")
                    )
                self.assertEqual(len(warnings), 1)
                self.assertIn("could not be checked", warnings[0])


if __name__ == "__main__":
    unittest.main()