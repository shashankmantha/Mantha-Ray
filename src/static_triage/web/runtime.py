"""Background scan execution and thread-safe state transitions.

ScanRuntime owns the only lock, the scan table, and the active scan ID.
Every state mutation happens under that lock.
"""

from __future__ import annotations

import json
import threading
from typing import Any
from uuid import uuid4

from ..host_scan import (
    DockerScanController,
    DockerScanRequest,
    HostScanError,
    ScanCancelled,
)
from .artifacts import load_case_artifacts
from .metadata import persist_session_metadata
from .state import (
    ACTIVE_STATES,
    SCAN_STAGE_NAMES,
    SCAN_STAGE_STATUSES,
    TERMINAL_STATES,
    WebScanState,
    now,
    stages_from_report,
)
from .validation import read_bounded_text


class ScanRuntime:
    """Run one hardened container scan at a time on a worker thread."""

    def __init__(
        self,
        controller: DockerScanController,
    ) -> None:
        self.controller = controller
        self._lock = threading.Lock()
        self._scans: dict[str, WebScanState] = {}
        self._active_scan_id: str | None = None

    def start(
        self,
        request: DockerScanRequest,
    ) -> dict[str, Any]:
        """Create a scan record and start its worker thread."""

        with self._lock:
            if self._active_scan_id is not None:
                active = self._scans[
                    self._active_scan_id
                ]

                if active.state in ACTIVE_STATES:
                    raise HostScanError(
                        "A scan is already running."
                    )

            scan_id = f"scan-{uuid4().hex[:12]}"

            state = WebScanState(
                scan_id=scan_id,
                source_directory=str(
                    request.source_directory
                ),
                results_directory=str(
                    request.results_directory
                ),
            )

            state.events.append(
                {
                    "time": state.created_at,
                    "message": state.message,
                }
            )

            self._scans[scan_id] = state
            self._active_scan_id = scan_id

        threading.Thread(
            target=self._run_scan,
            args=(scan_id, request),
            daemon=True,
        ).start()

        return self.get(scan_id)

    def get(
        self,
        scan_id: str,
    ) -> dict[str, Any]:
        """Return a detached representation of a scan."""

        with self._lock:
            state = self._scans.get(scan_id)

            if state is None:
                raise HostScanError(
                    "The requested scan does not exist."
                )

            return state.to_dict()

    def cancel(
        self,
        scan_id: str,
    ) -> dict[str, Any]:
        """Request cancellation of an active scan."""

        with self._lock:
            state = self._scans.get(scan_id)

            if state is None:
                raise HostScanError(
                    "The requested scan does not exist."
                )

            if state.state not in ACTIVE_STATES:
                return state.to_dict()

            self._record_locked(
                state,
                "cancelling",
                "Cancellation requested...",
            )

        self.controller.cancel()

        return self.get(scan_id)

    def shutdown(self) -> None:
        """Stop an active container before the server exits."""

        with self._lock:
            scan_id = self._active_scan_id

            active = (
                self._scans.get(scan_id)
                if scan_id is not None
                else None
            )

        if (
            active is not None
            and active.state in ACTIVE_STATES
        ):
            self.controller.cancel()

    def _run_scan(
        self,
        scan_id: str,
        request: DockerScanRequest,
    ) -> None:
        try:
            self._update(
                scan_id,
                "preflight",
                "Checking Docker and the analysis image...",
            )

            version = self.controller.preflight()

            self._append(
                scan_id,
                f"Docker server {version} is available.",
            )

            if self.get(scan_id)["state"] == "cancelling":
                raise ScanCancelled(
                    "The scan was cancelled."
                )

            self._update(
                scan_id,
                "running",
                (
                    "ClamAV, capa, and FLOSS are "
                    "analyzing the folder..."
                ),
            )

            result = self.controller.scan(
                request,
                on_status=lambda message: self._append(
                    scan_id,
                    message,
                ),
                on_progress=(
                    lambda stage, status, message:
                    self._stage(
                        scan_id,
                        stage,
                        status,
                        message,
                    )
                ),
            )

            report_json_path = (
                result.case_directory / "report.json"
            )

            if not report_json_path.is_file():
                raise HostScanError(
                    "The scan finished, but report.json "
                    "is missing."
                )

            report_json = json.loads(
                read_bounded_text(report_json_path)
            )

            if not isinstance(report_json, dict):
                raise HostScanError(
                    "The generated JSON report is invalid."
                )

            report_markdown = read_bounded_text(
                result.report_path
            )

            payload = {
                "case_id": result.case_id,
                "status": result.status,
                "case_directory": str(
                    result.case_directory
                ),
                "report_path": str(
                    result.report_path
                ),
                "report": report_json,
                "report_markdown": report_markdown,
                "artifacts": load_case_artifacts(
                    result.case_directory
                ),
            }

            self._complete(scan_id, payload)

        except ScanCancelled:
            self._update(
                scan_id,
                "cancelled",
                "The scan was cancelled.",
            )

        except Exception as exc:
            self._fail(
                scan_id,
                (
                    "Unexpected scan worker error: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

    def _append(
        self,
        scan_id: str,
        message: str,
    ) -> None:
        with self._lock:
            state = self._scans[scan_id]
            state.message = message
            state.updated_at = now()
            state.events.append(
                {
             "time": state.updated_at,
                    "message": message,
                }
            )

    def _stage(
        self,
        scan_id: str,
        stage: str,
        status: str,
        message: str,
    ) -> None:
        """Record one validated analyzer-stage transition."""

        if (
            stage not in SCAN_STAGE_NAMES
            or status not in SCAN_STAGE_STATUSES
        ):
            return

        with self._lock:
            state = self._scans[scan_id]

            if state.state in TERMINAL_STATES:
                return

            state.stages[stage] = status
            state.message = message
            state.updated_at = now()
            state.events.append(
                {
                    "time": state.updated_at,
                    "message": message,
                }
            )

    def _update(
        self,
        scan_id: str,
        status: str,
        message: str,
    ) -> None:
        with self._lock:
            state = self._scans[scan_id]

            if status == "cancelled":
                for stage, stage_status in (
                    state.stages.items()
                ):
                    if stage_status == "running":
                        state.stages[stage] = "cancelled"

            self._record_locked(
                state,
                status,
                message,
            )

            if (
                status in TERMINAL_STATES
                and self._active_scan_id == scan_id
            ):
                self._active_scan_id = None

    @staticmethod
    def _record_locked(
        state: WebScanState,
        status: str,
        message: str,
    ) -> None:
        state.state = status
        state.message = message
        state.updated_at = now()
        state.events.append(
            {
                "time": state.updated_at,
                "message": message,
            }
        )

    def _complete(
        self,
        scan_id: str,
        result: dict[str, Any],
    ) -> None:
        with self._lock:
            state = self._scans[scan_id]
            state.result = result

            report = result.get("report")

            if isinstance(report, dict):
                state.stages = stages_from_report(
                    report
                )

            self._record_locked(
                state,
                "completed",
                "Analysis complete.",
            )

            self._active_scan_id = None

            try:
                persist_session_metadata(
                    state.to_dict()
                )
            except OSError:
                # Reports remain authoritative even if the
                # optional browser metadata cannot be saved.
                pass

    def _fail(
        self,
        scan_id: str,
        error: str,
    ) -> None:
        with self._lock:
            state = self._scans[scan_id]
            state.error = error

            for stage, status in state.stages.items():
                if status == "running":
                    state.stages[stage] = "error"

            self._record_locked(
                state,
                "failed",
                error,
            )

            self._active_scan_id = None