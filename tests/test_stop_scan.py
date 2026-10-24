from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from static_triage import stop_request
from static_triage.capa import CapaResult, CapaStatus, _normalize_result, run_capa_batch
from static_triage.case_summary import summarize
from static_triage.container import controller as controller_module
from static_triage.container.controller import DockerScanController
from static_triage.deduplication import group_entries_by_sha256
from static_triage.file_progress import finished_message
from static_triage.models import EntryKind, EntryState, InventoryEntry, RoutingClass
from static_triage.parallel import run_groups
from static_triage.runner import CommandResult, run_command
from static_triage.web.runtime import ScanRuntime
from static_triage.web.state import WebScanState

ROOT = Path(__file__).resolve().parents[1]


def entry(path, size):
    return InventoryEntry(
        relative_path=path,
        kind=EntryKind.REGULAR_FILE,
        state=EntryState.INVENTORIED,
        sha256=(path.encode().hex() * 64)[:64],
        size_bytes=size,
        routing_class=RoutingClass.PE_EXECUTABLE,
    )


class StopTestCase(unittest.TestCase):
    def setUp(self) -> None:
        stop_request.reset()
        self.addCleanup(stop_request.reset)


class RunnerTests(StopTestCase):
    def test_stoppable_command_ends_promptly(self) -> None:
        threading.Timer(0.3, stop_request.request).start()
        started = time.monotonic()
        result = run_command(
            ["sleep", "30"], timeout_seconds=60, max_output_bytes=100, stoppable=True
        )
        self.assertTrue(result.stopped)
        self.assertFalse(result.timed_out)
        self.assertLess(time.monotonic() - started, 5)

    def test_unstoppable_command_ignores_requests(self) -> None:
        stop_request.request()
        result = run_command(["true"], timeout_seconds=10, max_output_bytes=100)
        self.assertFalse(result.stopped)
        self.assertEqual(result.return_code, 0)

    def test_nothing_starts_once_stopped(self) -> None:
        stop_request.request()
        result = run_command(
            ["sleep", "30"], timeout_seconds=60, max_output_bytes=100, stoppable=True
        )
        self.assertTrue(result.stopped)
        self.assertEqual(result.duration_seconds, 0.0)

    def test_timeout_still_works_when_stoppable(self) -> None:
        result = run_command(
            ["sleep", "30"], timeout_seconds=0.6, max_output_bytes=100, stoppable=True
        )
        self.assertTrue(result.timed_out)
        self.assertFalse(result.stopped)


class SignalTests(StopTestCase):
    def test_signal_stops_a_real_scan_process(self) -> None:
        # A separate process installs the handler and runs a long stoppable
        # command, exactly as the scan container does; SIGUSR1 must end the
        # command quickly and leave the process alive to finish its work.
        script = textwrap.dedent(
            """
            import sys, time
            sys.path.insert(0, sys.argv[1])
            from static_triage import stop_request
            from static_triage.runner import run_command
            stop_request.install()
            print("ready", flush=True)
            result = run_command(["sleep", "30"], timeout_seconds=60,
                                 max_output_bytes=100, stoppable=True)
            print("stopped" if result.stopped else "not stopped", flush=True)
            """
        )
        process = subprocess.Popen(
            [sys.executable, "-c", script, str(ROOT / "src")],
            stdout=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(process.stdout.readline().strip(), "ready")
        os.kill(process.pid, signal.SIGUSR1)
        output, _ = process.communicate(timeout=10)
        self.assertEqual(output.strip(), "stopped")
        self.assertEqual(process.returncode, 0)


class SchedulerTests(StopTestCase):
    def test_no_new_files_after_stop(self) -> None:
        groups = group_entries_by_sha256([entry(f"f{i}.dll", 10 + i) for i in range(6)])
        started: list[str] = []

        def analyze(group, timeout):
            started.append(group.representative.relative_path)
            if len(started) == 2:
                stop_request.request()
            return "ok"

        run = run_groups(
            groups, analyze, label="capa", workers=1, total_timeout_seconds=3600,
            timeout_for=lambda g: 300.0, outcome=lambda r: (True, False, 1.0),
            clock=time.monotonic,
        )
        self.assertEqual(len(started), 2)
        self.assertEqual(len(run.not_started), 4)

    def test_no_memory_retry_after_stop(self) -> None:
        barrier = threading.Barrier(2, timeout=5)
        calls: list[str] = []

        def analyze(group, timeout):
            calls.append(group.representative.relative_path)
            barrier.wait()
            stop_request.request()
            return "killed"

        run = run_groups(
            group_entries_by_sha256([entry("a.dll", 1), entry("b.dll", 2)]),
            analyze, label="capa", workers=2, total_timeout_seconds=3600,
            timeout_for=lambda g: 300.0, outcome=lambda r: (False, False, 1.0),
            clock=time.monotonic, retry_alone_if=lambda r: r == "killed",
        )
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(run.finished), 2)


class AnalyzerTests(StopTestCase):
    def test_stopped_command_result(self) -> None:
        execution = CommandResult(
            command=("capa",), return_code=-9, stdout="", stderr="",
            timed_out=False, output_truncated=False, duration_seconds=12.0,
            stopped=True,
        )
        result = _normalize_result(execution, "DoorKickers2.exe")
        self.assertTrue(result.stopped_by_user)
        self.assertIn("stopped by the user", result.error)
        self.assertNotIn("memory", result.error)

    def test_batch_after_stop(self) -> None:
        def fake(target, scan_root, **_):
            name = target.relative_to(scan_root).as_posix()
            stop_request.request()
            return CapaResult(
                status=CapaStatus.ERROR, complete=False, relative_path=name,
                return_code=-9, capabilities=(), timed_out=False,
                output_truncated=False, duration_seconds=5.0, stdout="", stderr="",
                error="stopped", stopped_by_user=True,
            )

        with (
            patch("static_triage.capa.run_capa", side_effect=fake),
            tempfile.TemporaryDirectory() as temporary,
        ):
            batch = run_capa_batch(
                [entry("a.dll", 10), entry("b.dll", 20), entry("c.dll", 30)],
                Path(temporary),
                workers=2,
            )
        payload = batch.to_dict()
        self.assertFalse(batch.complete)
        self.assertIn("because the scan was stopped by the user", batch.error)
        for result in payload["results"]:
            self.assertTrue(result["stopped_by_user"])
            self.assertFalse(result["needs_more_memory"])
            self.assertFalse(result["retried_alone"])

    def test_progress_message(self) -> None:
        group = group_entries_by_sha256([entry("a.dll", 10)])[0]
        self.assertEqual(
            finished_message(
                "capa", 3, 9, group, complete=False, timed_out=False,
                duration_seconds=65, stopped_by_user=True,
            ),
            "capa 3/9 stopped by the user after 1 min 5 s: a.dll",
        )

    def test_summary_labels(self) -> None:
        import json

        report = {
            "status": "incomplete",
            "warnings": [
                "The scan was stopped by the user before it finished. "
                "This report covers only the work finished by then."
            ],
            "analyzers": {"capa": {"results": [
                {"relative_path": "a.exe", "complete": False, "timed_out": False,
                 "duration_seconds": 30, "analysis_position": 1,
                 "stopped_by_user": True, "return_code": -9},
            ]}},
        }
        with tempfile.TemporaryDirectory() as temporary:
            case = Path(temporary) / "case-20261022T000000Z-aaaaaaaa"
            case.mkdir()
            (case / "report.json").write_text(json.dumps(report))
            text = summarize(case)
        self.assertIn("1 stopped by you", text)
        self.assertIn("Stopped  by you before it finished", text)
        self.assertNotIn("out of memory", text)


class ControllerTests(unittest.TestCase):
    def controller_with_running_scan(self, age_seconds: float) -> DockerScanController:
        controller = DockerScanController()
        controller._process = MagicMock()
        controller._process.wait.side_effect = subprocess.TimeoutExpired("docker", 1)
        controller._container_name = "static-triage-gui-abc123"
        controller._started_at = time.monotonic() - age_seconds
        return controller

    def test_stop_sends_the_signal(self) -> None:
        controller = self.controller_with_running_scan(60)
        with (
            patch.object(controller, "_resolve_engine", return_value="/usr/bin/docker"),
            patch("static_triage.container.controller.subprocess.run") as run,
            patch.object(controller_module, "STOP_GRACE_SECONDS", 0.01),
            patch.object(controller, "cancel") as cancel,
        ):
            run.return_value = MagicMock(returncode=0)
            self.assertEqual(controller.stop(), "stopping")
            time.sleep(0.2)
        self.assertEqual(
            run.call_args.args[0],
            ["/usr/bin/docker", "kill", "--signal", "USR1", "static-triage-gui-abc123"],
        )
        # The fake container never exits, so the watchdog cancels it.
        cancel.assert_called_once()

    def test_stop_right_after_start_cancels(self) -> None:
        controller = self.controller_with_running_scan(2)
        with patch.object(controller, "cancel") as cancel:
            self.assertEqual(controller.stop(), "cancelled")
        cancel.assert_called_once()

    def test_undeliverable_signal_cancels(self) -> None:
        controller = self.controller_with_running_scan(60)
        with (
            patch.object(controller, "_resolve_engine", return_value="/usr/bin/docker"),
            patch("static_triage.container.controller.subprocess.run") as run,
            patch.object(controller, "cancel") as cancel,
        ):
            run.return_value = MagicMock(returncode=1)
            self.assertEqual(controller.stop(), "cancelled")
        cancel.assert_called_once()


class RuntimeTests(unittest.TestCase):
    def runtime_with(self, state: str) -> tuple[ScanRuntime, MagicMock]:
        controller = MagicMock()
        controller.stop.return_value = "stopping"
        runtime = ScanRuntime(controller)
        runtime._scans["scan-1"] = WebScanState(
            scan_id="scan-1", source_directory="/s", results_directory="/r", state=state,
        )
        runtime._active_scan_id = "scan-1"
        return runtime, controller

    def test_running_scan_stops(self) -> None:
        runtime, controller = self.runtime_with("running")
        self.assertEqual(runtime.stop("scan-1")["state"], "stopping")
        controller.stop.assert_called_once()

    def test_scan_before_container_is_cancelled(self) -> None:
        runtime, controller = self.runtime_with("preflight")
        self.assertEqual(runtime.stop("scan-1")["state"], "cancelling")
        controller.cancel.assert_called_once()
        controller.stop.assert_not_called()

    def test_stop_is_idempotent(self) -> None:
        runtime, controller = self.runtime_with("stopping")
        runtime.stop("scan-1")
        controller.stop.assert_not_called()

    def test_finished_scan_untouched(self) -> None:
        runtime, controller = self.runtime_with("completed")
        self.assertEqual(runtime.stop("scan-1")["state"], "completed")
        controller.stop.assert_not_called()


class ScriptTests(unittest.TestCase):
    def test_script_help_and_confirmation(self) -> None:
        script = ROOT / "scripts" / "stop-scan.sh"
        self.assertTrue(os.access(script, os.X_OK))
        help_text = subprocess.run(
            [str(script), "--help"], capture_output=True, text=True, timeout=30
        ).stdout
        self.assertIn("report of the work finished so far", help_text)
        with tempfile.TemporaryDirectory() as temporary:
            fake = Path(temporary) / "docker"
            log = Path(temporary) / "calls"
            fake.write_text(
                "#!/usr/bin/env bash\n"
                f'echo "$*" >> {log}\n'
                'if [[ "$1" == "ps" ]]; then echo static-triage-gui-abc123; fi\n'
            )
            fake.chmod(0o755)
            env = {**os.environ, "MANTHA_RAY_ENGINE": str(fake)}
            refused = subprocess.run(
                [str(script)], input="yes\n", capture_output=True, text=True,
                env=env, timeout=30,
            )
            self.assertEqual(refused.returncode, 1)
            self.assertNotIn("kill", log.read_text())
            self.assertIn("Kept scanning", refused.stdout)

    def test_script_confirmed_stop(self) -> None:
        script = ROOT / "scripts" / "stop-scan.sh"
        with tempfile.TemporaryDirectory() as temporary:
            fake = Path(temporary) / "docker"
            log = Path(temporary) / "calls"
            seen = Path(temporary) / "seen"
            # The first `ps` lists the scan; after that it has exited.
            fake.write_text(
                "#!/usr/bin/env bash\n"
                f'echo "$*" >> {log}\n'
                'if [[ "$1" == "ps" ]]; then\n'
                f'  if [[ ! -e {seen} ]]; then touch {seen}; echo static-triage-gui-abc123; fi\n'
                "fi\n"
            )
            fake.chmod(0o755)
            env = {**os.environ, "MANTHA_RAY_ENGINE": str(fake)}
            done = subprocess.run(
                [str(script)], input="stop\n", capture_output=True, text=True,
                env=env, timeout=30,
            )
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn("kill --signal USR1 static-triage-gui-abc123", log.read_text())
            self.assertIn("report was saved", done.stdout)


if __name__ == "__main__":
    unittest.main()
