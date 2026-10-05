"""Public coordinator used by the web API.

ScanService validates browser requests and delegates: saved-case access
to the history module and live scans to ScanRuntime.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..host_scan import (
    DockerScanController,
    DockerScanRequest,
    HostScanError,
    validate_request,
)
from .history import list_cases, load_saved_case
from .runtime import ScanRuntime
from .validation import (
    paths_overlap,
    resolve_case_directory,
    resolve_history_root,
)


class ScanService:
    """Coordinate one hardened container scan at a time."""

    def __init__(
        self,
        controller: DockerScanController,
    ) -> None:
        self.controller = controller
        self._runtime = ScanRuntime(controller)

    def prepare_request(
        self,
        source_directory: str,
        results_directory: str,
    ) -> DockerScanRequest:
        """Validate paths before creating the results directory."""

        try:
            source = Path(
                source_directory
            ).expanduser().resolve(strict=True)

            results = Path(
                results_directory
            ).expanduser().resolve(strict=False)

        except OSError as exc:
            raise HostScanError(
                "The selected folders could not be resolved."
            ) from exc

        if not source.is_dir():
            raise HostScanError(
                "The scan source must be a directory."
            )

        if paths_overlap(source, results):
            raise HostScanError(
                "The scan source and results destination "
                "cannot overlap."
            )

        try:
            results.mkdir(
                parents=True,
                exist_ok=True,
            )
        except OSError as exc:
            raise HostScanError(
                "The results directory could not be created."
            ) from exc

        return validate_request(
            DockerScanRequest(
                source_directory=source,
                results_directory=results,
                image=self.controller.image,
            )
        )

    def list_cases(
        self,
        results_directory: str,
    ) -> dict[str, Any]:
        """List bounded summaries for valid saved cases."""

        return list_cases(results_directory)

    def load_case(
        self,
        results_directory: str,
        case_id: str,
    ) -> dict[str, Any]:
        """Load one saved case as a completed scan state."""

        return load_saved_case(
            results_directory,
            case_id,
        )

    def saved_case_directory(
        self,
        results_directory: str,
        case_id: str,
    ) -> Path:
        """Return a validated saved case directory."""

        root = resolve_history_root(
            results_directory
        )
        return resolve_case_directory(
            root,
            case_id,
        )

    def start(
        self,
        source_directory: str,
        results_directory: str,
    ) -> dict[str, Any]:
        """Validate the request, then start a background scan."""

        request = self.prepare_request(
            source_directory,
            results_directory,
        )
        return self._runtime.start(request)

    def get(
        self,
        scan_id: str,
    ) -> dict[str, Any]:
        """Return a detached representation of a scan."""

        return self._runtime.get(scan_id)

    def cancel(
        self,
        scan_id: str,
    ) -> dict[str, Any]:
        """Request cancellation of an active scan."""

        return self._runtime.cancel(scan_id)

    def shutdown(self) -> None:
        """Stop an active container before the server exits."""

        self._runtime.shutdown()

    def case_directory(
        self,
        scan_id: str,
    ) -> Path:
        """Return the completed case directory."""

        state = self.get(scan_id)
        result = state.get("result")

        if not isinstance(result, dict):
            raise HostScanError(
                "The scan has no completed case directory."
            )

        case_id = result.get("case_id")
        results_directory = state.get(
            "results_directory"
        )

        if (
            not isinstance(case_id, str)
            or not isinstance(
                results_directory,
                str,
            )
        ):
            raise HostScanError(
                "The scan has no completed case directory."
            )

        root = resolve_history_root(
            results_directory
        )
        return resolve_case_directory(
            root,
            case_id,
        )