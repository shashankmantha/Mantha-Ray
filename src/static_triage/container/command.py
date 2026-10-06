"""Validated scan requests and the fixed, hardened Docker command."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path


IMAGE_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._/:@-]*$"
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

    if not IMAGE_PATTERN.fullmatch(
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