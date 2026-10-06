"""Compatibility exports for the host-side Docker controller."""

from .container.command import (
    DockerScanRequest,
    HostScanError,
    ScanCancelled,
    build_docker_command,
    validate_request,
)
from .container.controller import DockerScanController
from .container.progress import parse_progress_event
from .container.result import DockerScanResult, parse_scan_output

__all__ = [
    "DockerScanController",
    "DockerScanRequest",
    "DockerScanResult",
    "HostScanError",
    "ScanCancelled",
    "build_docker_command",
    "parse_progress_event",
    "parse_scan_output",
    "validate_request",
]