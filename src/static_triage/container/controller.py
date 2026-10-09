"""Docker preflight, process lifecycle, stream capture, and cancellation."""

from __future__ import annotations

import shutil
import subprocess
import threading
from typing import Callable
from uuid import uuid4

from .command import (
    IMAGE_PATTERN,
    DockerScanRequest,
    HostScanError,
    ScanCancelled,
    build_docker_command,
    validate_request,
)
from ..resource_profiles import (
    ResourceProfile,
    ResourceProfileError,
    check_capacity,
)
from .progress import parse_progress_event
from .result import DockerScanResult, parse_scan_output


MAX_CAPTURE_BYTES = 2 * 1024 * 1024


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

        if not IMAGE_PATTERN.fullmatch(
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

    def docker_capacity(
        self,
    ) -> tuple[float, int] | None:
        """Return Docker's CPU count and memory, or None if unknown.

        Docker Desktop runs containers in a virtual machine that can be
        smaller than the host, so capacity comes from Docker itself.
        """

        engine_path = self._resolve_engine()

        try:
            info = subprocess.run(
                [
                    engine_path,
                    "info",
                    "--format",
                    "{{.NCPU}} {{.MemTotal}}",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (
            OSError,
            subprocess.TimeoutExpired,
        ):
            return None

        if info.returncode != 0:
            return None

        parts = info.stdout.split()
        if len(parts) != 2:
            return None
        try:
            cpus = float(int(parts[0]))
            memory = int(parts[1])
        except ValueError:
            return None
        if cpus <= 0 or memory <= 0:
            return None
        return cpus, memory

    def check_resources(
        self,
        profile: ResourceProfile,
    ) -> list[str]:
        """Reject profiles Docker cannot satisfy; return warnings."""

        capacity = self.docker_capacity()
        if capacity is None:
            return [
                "Docker did not report its CPU and memory capacity, "
                "so the resource profile could not be checked "
                "against it."
            ]

        cpus, memory = capacity
        try:
            return check_capacity(
                profile,
                cpus_available=cpus,
                memory_bytes_available=memory,
            )
        except ResourceProfileError as exc:
            raise HostScanError(str(exc)) from exc

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

        warnings = self.check_resources(
            validated.resource_profile
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
            for warning in warnings:
                on_status(warning)
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
                    > MAX_CAPTURE_BYTES
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

        if (
            process.returncode == 2
            and "--resource-profile" in stderr
            and "unrecognized arguments" in stderr
        ):
            raise HostScanError(
                "The analysis image is older than this version "
                "of Mantha Ray. Run ./scripts/setup.sh to "
                "rebuild it."
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