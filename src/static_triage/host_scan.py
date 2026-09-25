"""Host-side Docker controller used by the graphical interface."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from uuid import uuid4


_CASE_ID_PATTERN = re.compile(
    r"^case-\d{8}T\d{6}Z-[0-9a-f]{8}$"
)

_IMAGE_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._/:@-]*$"
)

_MAX_CAPTURE_BYTES = 2 * 1024 * 1024

_PROGRESS_STAGES = frozenset(
    {
        "inventory",
        "clamav",
        "capa",
        "floss",
        "report",
    }
)

_PROGRESS_STATUSES = frozenset(
    {
        "waiting",
        "running",
        "completed",
        "incomplete",
        "unavailable",
        "error",
    }
)


class HostScanError(RuntimeError):
    """A safe, user-facing host controller failure."""


class ScanCancelled(HostScanError):
    """The user cancelled the active container scan."""


@dataclass(frozen=True, slots=True)
class DockerScanRequest:
    """Validated host inputs for one containerized scan."""

    source_directory: Path
    results_directory: Path
    image: str = "static-triage:core"
    timeout_seconds: int = 4 * 60 * 60


@dataclass(frozen=True, slots=True)
class DockerScanResult:
    """Host paths derived from a successful scanner response."""

    case_id: str
    status: str
    case_directory: Path
    report_path: Path
    output: str


def _paths_overlap(
    first: Path,
    second: Path,
) -> bool:
    return (
        first == second
        or first.is_relative_to(second)
        or second.is_relative_to(first)
    )


def validate_request(
    request: DockerScanRequest,
) -> DockerScanRequest:
    """Resolve and validate all host-controlled scan inputs."""

    try:
        source = (
            request.source_directory
            .expanduser()
            .resolve(strict=True)
        )
    except OSError as exc:
        raise HostScanError(
            "The selected scan folder does not exist "
            "or cannot be read."
        ) from exc

    try:
        results = (
            request.results_directory
            .expanduser()
            .resolve(strict=True)
        )
    except OSError as exc:
        raise HostScanError(
            "The selected results folder does not exist."
        ) from exc

    if not source.is_dir():
        raise HostScanError(
            "The scan source must be a directory."
        )

    if not results.is_dir():
        raise HostScanError(
            "The results destination must be a directory."
        )

    if _paths_overlap(source, results):
        raise HostScanError(
            "The scan source and results destination "
            "cannot overlap."
        )

    if not os.access(
        source,
        os.R_OK | os.X_OK,
    ):
        raise HostScanError(
            "The selected scan folder is not readable."
        )

    if not os.access(
        results,
        os.W_OK | os.X_OK,
    ):
        raise HostScanError(
            "The selected results folder is not writable."
        )

    if (
        "," in str(source)
        or "," in str(results)
    ):
        raise HostScanError(
            "Docker bind mounts do not support commas "
            "in selected paths."
        )

    if not _IMAGE_PATTERN.fullmatch(
        request.image
    ):
        raise HostScanError(
            "The configured container image name is invalid."
        )

    if request.timeout_seconds <= 0:
        raise HostScanError(
            "The scan timeout must be greater than zero."
        )

    return DockerScanRequest(
        source_directory=source,
        results_directory=results,
        image=request.image,
        timeout_seconds=request.timeout_seconds,
    )


def build_docker_command(
    request: DockerScanRequest,
    engine_path: str,
    container_name: str,
) -> list[str]:
    """Build a fixed-argument hardened container command."""

    source_mount = (
        "type=bind,source="
        f"{request.source_directory},"
        "target=/staging/input,readonly"
    )

    results_mount = (
        "type=bind,source="
        f"{request.results_directory},"
        "target=/results"
    )

    return [
        engine_path,
        "run",
        "--rm",
        "--name",
        container_name,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--security-opt",
        "label=disable",
        "--pids-limit",
        "256",
        "--memory",
        "4g",
        "--cpus",
        "2",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--tmpfs",
        (
            "/tmp:rw,noexec,nosuid,nodev,"
            "size=512m,mode=1777"
        ),
        "--mount",
        source_mount,
        "--mount",
        results_mount,
        request.image,
        "scan",
        "input",
        "--staging-root",
        "/staging",
        "--results-root",
        "/results",
        "--progress-jsonl",
    ]


def parse_progress_event(
    line: str,
) -> tuple[str, str, str] | None:
    """Parse one bounded scanner progress event."""

    if len(line) > 8192:
        return None

    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None

    if payload.get("type") != "progress":
        return None

    stage = payload.get("stage")
    status = payload.get("status")
    message = payload.get("message")

    if (
        not isinstance(stage, str)
        or stage not in _PROGRESS_STAGES
        or not isinstance(status, str)
        or status not in _PROGRESS_STATUSES
        or not isinstance(message, str)
        or not message
        or len(message) > 4096
    ):
        return None

    return stage, status, message


def parse_scan_output(
    stdout: str,
    stderr: str,
    results_directory: Path,
) -> DockerScanResult:
    """Parse scanner JSON without trusting returned paths."""

    response: dict[str, object] | None = None

    for line in reversed(
        stdout.splitlines()
    ):
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue

        if (
            isinstance(candidate, dict)
            and "ok" in candidate
        ):
            response = candidate
            break

    if response is None:
        detail = (
            stderr.strip()
            or stdout.strip()
        )

        if len(detail) > 500:
            detail = detail[-500:]

        message = (
            "The scanner did not return a valid result."
        )

        if detail:
            message = f"{message} {detail}"

        raise HostScanError(message)

    if response.get("ok") is not True:
        error = response.get("error")

        raise HostScanError(
            str(error)
            if error
            else "The scanner reported a failure."
        )

    case_id = response.get("case_id")
    status = response.get("status")

    if (
        not isinstance(case_id, str)
        or not _CASE_ID_PATTERN.fullmatch(
            case_id
        )
    ):
        raise HostScanError(
            "The scanner returned an invalid case ID."
        )

    if (
        not isinstance(status, str)
        or not status
    ):
        raise HostScanError(
            "The scanner returned an invalid status."
        )

    case_directory = (
        results_directory / case_id
    )

    report_path = (
        case_directory / "report.md"
    )

    if not report_path.is_file():
        raise HostScanError(
            "The scan finished, but its Markdown "
            "report is missing."
        )

    combined = stdout

    if stderr:
        combined = (
            f"{stdout.rstrip()}\n"
            f"{stderr.rstrip()}\n"
        )

    return DockerScanResult(
        case_id=case_id,
        status=status,
        case_directory=case_directory,
        report_path=report_path,
        output=combined,
    )


class DockerScanController:
    """Run and cancel one hardened Docker scan at a time."""

    def __init__(
        self,
        engine: str = "docker",
        image: str = "static-triage:core",
    ) -> None:
        self.engine = engine
        self.image = image

        self._lock = threading.Lock()

        self._process: (
            subprocess.Popen[str] | None
        ) = None

        self._container_name: (
            str | None
        ) = None

        self._cancel_requested = False

    def _resolve_engine(self) -> str:
        engine_path = shutil.which(
            self.engine
        )

        if engine_path is None:
            raise HostScanError(
                f"Container engine '{self.engine}' "
                "was not found."
            )

        return engine_path

    def preflight(self) -> str:
        """Confirm Docker and the worker image are available."""

        if not _IMAGE_PATTERN.fullmatch(
            self.image
        ):
            raise HostScanError(
                "The configured container image "
                "name is invalid."
            )

        engine_path = self._resolve_engine()

        try:
            version = subprocess.run(
                [
                    engine_path,
                    "version",
                    "--format",
                    "{{.Server.Version}}",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (
            OSError,
            subprocess.TimeoutExpired,
        ) as exc:
            raise HostScanError(
                "Docker did not respond to its "
                "preflight check."
            ) from exc

        if version.returncode != 0:
            detail = version.stderr.strip()

            raise HostScanError(
                "Docker is installed, but its daemon "
                "is unavailable."
                + (
                    f" {detail}"
                    if detail
                    else ""
                )
            )

        try:
            image = subprocess.run(
                [
                    engine_path,
                    "image",
                    "inspect",
                    self.image,
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15,
            )
        except (
            OSError,
            subprocess.TimeoutExpired,
        ) as exc:
            raise HostScanError(
                "Docker could not inspect the "
                "analysis image."
            ) from exc

        if image.returncode != 0:
            raise HostScanError(
                f"Container image '{self.image}' "
                "is not available. Build it before "
                "starting a scan."
            )

        return (
            version.stdout.strip()
            or "available"
        )

    def scan(
        self,
        request: DockerScanRequest,
        on_status: (
            Callable[[str], None] | None
        ) = None,
        on_progress: (
            Callable[[str, str, str], None]
            | None
        ) = None,
    ) -> DockerScanResult:
        """Run a scan synchronously in a worker thread."""

        validated = validate_request(
            request
        )

        engine_path = (
            self._resolve_engine()
        )

        container_name = (
            "static-triage-gui-"
            + uuid4().hex[:12]
        )

        command = build_docker_command(
            validated,
            engine_path,
            container_name,
        )

        with self._lock:
            if (
                self._process is not None
                or self._container_name
                is not None
            ):
                raise HostScanError(
                    "A scan is already running."
                )

            self._cancel_requested = False
            self._container_name = (
                container_name
            )

        if on_status is not None:
            on_status(
                "Starting the isolated "
                "analysis container..."
            )

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
            )
        except OSError as exc:
            with self._lock:
                self._container_name = None

            raise HostScanError(
                "Docker could not start the "
                "analysis container."
            ) from exc

        with self._lock:
            self._process = process
            cancelled_before_start = (
                self._cancel_requested
            )

        if cancelled_before_start:
            self.cancel()

        stdout_parts: list[str] = []
        stderr_parts: list[str] = []

        capture_lock = threading.Lock()
        captured_bytes = 0
        capture_exceeded = threading.Event()

        def capture(
            destination: list[str],
            text: str,
        ) -> None:
            nonlocal captured_bytes

            size = len(
                text.encode(
                    "utf-8",
                    errors="replace",
                )
            )

            with capture_lock:
                if (
                    captured_bytes + size
                    > _MAX_CAPTURE_BYTES
                ):
                    capture_exceeded.set()
                    return

                captured_bytes += size
                destination.append(text)

        def read_stdout() -> None:
            if process.stdout is None:
                return

            try:
                for line in process.stdout:
                    capture(
                        stdout_parts,
                        line,
                    )

                    progress = (
                        parse_progress_event(
                            line
                        )
                    )

                    if (
                        progress is not None
                        and on_progress
                        is not None
                    ):
                        on_progress(*progress)

            except (OSError, ValueError):
                return

        def read_stderr() -> None:
            if process.stderr is None:
                return

            try:
                for line in process.stderr:
                    capture(
                        stderr_parts,
                        line,
                    )

            except (OSError, ValueError):
                return

        stdout_thread = threading.Thread(
            target=read_stdout,
            name="mantha-ray-stdout",
            daemon=True,
        )

        stderr_thread = threading.Thread(
            target=read_stderr,
            name="mantha-ray-stderr",
            daemon=True,
        )

        stdout_thread.start()
        stderr_thread.start()

        timed_out = False

        try:
            process.wait(
                timeout=(
                    validated.timeout_seconds
                )
            )

        except subprocess.TimeoutExpired:
            timed_out = True
            self.cancel()

            if process.poll() is None:
                process.kill()

            process.wait()

        finally:
            stdout_thread.join(
                timeout=5
            )

            stderr_thread.join(
                timeout=5
            )

            with self._lock:
                cancelled = (
                    self._cancel_requested
                )

                self._process = None
                self._container_name = None

        stdout = "".join(stdout_parts)
        stderr = "".join(stderr_parts)

        if timed_out:
            raise HostScanError(
                "The scan exceeded its host-side "
                "time limit."
            )

        if cancelled:
            raise ScanCancelled(
                "The scan was cancelled."
            )

        if capture_exceeded.is_set():
            raise HostScanError(
                "The container produced more output "
                "than the host limit."
            )

        if process.returncode != 0:
            detail = (
                stderr.strip()
                or stdout.strip()
            )

            if len(detail) > 500:
                detail = detail[-500:]

            raise HostScanError(
                "The analysis container exited "
                f"with code {process.returncode}."
                + (
                    f" {detail}"
                    if detail
                    else ""
                )
            )

        if on_status is not None:
            on_status(
                "Analysis complete; "
                "loading the report..."
            )

        return parse_scan_output(
            stdout,
            stderr,
            validated.results_directory,
        )

    def cancel(self) -> None:
        """Request cancellation of the active container."""

        with self._lock:
            process = self._process
            container_name = (
                self._container_name
            )

            self._cancel_requested = True

        if (
            process is None
            or container_name is None
        ):
            return

        try:
            engine_path = (
                self._resolve_engine()
            )

            subprocess.run(
                [
                    engine_path,
                    "stop",
                    "--time",
                    "5",
                    container_name,
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )

        except (
            HostScanError,
            OSError,
            subprocess.TimeoutExpired,
        ):
            pass

        if process.poll() is None:
            process.terminate()