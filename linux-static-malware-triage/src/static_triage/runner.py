"""Bounded execution of external analysis tools."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Mapping, Sequence


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Normalized result from an external command."""

    command: tuple[str, ...]
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool
    output_truncated: bool
    duration_seconds: float


class _BoundedCapture:
    """Capture a limited number of bytes while draining a pipe."""

    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max_bytes
        self.chunks: list[bytes] = []
        self.bytes_saved = 0
        self.truncated = False

    def add(self, chunk: bytes) -> None:
        remaining = self.max_bytes - self.bytes_saved

        if remaining <= 0:
            self.truncated = True
            return

        saved = chunk[:remaining]
        self.chunks.append(saved)
        self.bytes_saved += len(saved)

        if len(saved) < len(chunk):
            self.truncated = True

    def text(self) -> str:
        return b"".join(self.chunks).decode(
            "utf-8",
            errors="replace",
        )


def _drain_pipe(
    stream: BinaryIO,
    capture: _BoundedCapture,
) -> None:
    """Drain a pipe without retaining unlimited output."""

    try:
        while True:
            chunk = stream.read(64 * 1024)

            if not chunk:
                break

            capture.add(chunk)
    except OSError:
        pass
    finally:
        stream.close()


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    grace_seconds: float = 0.5,
) -> None:
    """Terminate the command and any children it created."""

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return

    try:
        process.wait(timeout=grace_seconds)
        return
    except subprocess.TimeoutExpired:
        pass

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass

    process.wait()


def run_command(
    command: Sequence[str],
    *,
    timeout_seconds: float = 60.0,
    max_output_bytes: int = 1_000_000,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> CommandResult:
    """Run one command without a shell and bound its resources."""

    if not command:
        raise ValueError("command cannot be empty")

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    if max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be positive")

    normalized_command = tuple(str(item) for item in command)

    started = time.monotonic()

    process = subprocess.Popen(
        normalized_command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=dict(env) if env is not None else None,
        shell=False,
        start_new_session=True,
    )

    if process.stdout is None or process.stderr is None:
        _terminate_process_group(process)
        raise RuntimeError("failed to create command output pipes")

    stdout_capture = _BoundedCapture(max_output_bytes)
    stderr_capture = _BoundedCapture(max_output_bytes)

    stdout_thread = threading.Thread(
        target=_drain_pipe,
        args=(process.stdout, stdout_capture),
        daemon=True,
    )

    stderr_thread = threading.Thread(
        target=_drain_pipe,
        args=(process.stderr, stderr_capture),
        daemon=True,
    )

    stdout_thread.start()
    stderr_thread.start()

    timed_out = False

    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_group(process)

    stdout_thread.join()
    stderr_thread.join()

    duration = time.monotonic() - started

    return CommandResult(
        command=normalized_command,
        return_code=(
            process.returncode
            if process.returncode is not None
            else -1
        ),
        stdout=stdout_capture.text(),
        stderr=stderr_capture.text(),
        timed_out=timed_out,
        output_truncated=(
            stdout_capture.truncated
            or stderr_capture.truncated
        ),
        duration_seconds=duration,
    )