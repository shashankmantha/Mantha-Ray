"""Thread-safe scan state for the local Mantha Ray web application."""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from .host_scan import (
    DockerScanController,
    DockerScanRequest,
    HostScanError,
    ScanCancelled,
    validate_request,
)
from .web.artifacts import load_case_artifacts
from .web.history import list_cases, load_case_result
from .web.metadata import (
    metadata_events,
    metadata_string,
    persist_session_metadata,
    read_session_metadata,
)
from .web.validation import (
    case_created_at,
    paths_overlap,
    read_bounded_text,
    resolve_case_directory,
    resolve_history_root,
)


_ACTIVE_STATES = {
    "queued",
    "preflight",
    "running",
    "cancelling",
}
_TERMINAL_STATES = {
    "completed",
    "failed",
    "cancelled",
}

_SCAN_STAGE_NAMES = (
    "inventory",
    "clamav",
    "capa",
    "floss",
    "report",
)

_SCAN_STAGE_STATUSES = frozenset(
    {
        "waiting",
        "running",
        "completed",
        "incomplete",
        "unavailable",
        "error",
        "cancelled",
    }
)


def _waiting_stages() -> dict[str, str]:
    return {
        stage: "waiting"
        for stage in _SCAN_STAGE_NAMES
    }


def _stages_from_report(
    report: dict[str, Any],
) -> dict[str, str]:
    """Derive final stage health from an authoritative report."""

    stages = _waiting_stages()
    summary = report.get("summary")

    if isinstance(summary, dict):
        inventory_complete = (
            summary.get("errors", 0) == 0
            and summary.get("limit_exceeded", 0) == 0
        )
        stages["inventory"] = (
            "completed"
            if inventory_complete
            else "incomplete"
        )

    analyzers = report.get("analyzers")

    if isinstance(analyzers, dict):
        for name in ("clamav", "capa", "floss"):
            analyzer = analyzers.get(name)

            if not isinstance(analyzer, dict):
                continue

            analyzer_status = analyzer.get("status")

            if analyzer_status == "not_run":
                stages[name] = "unavailable"
            elif analyzer_status == "error":
                stages[name] = "error"
            elif analyzer.get("complete") is True:
                stages[name] = "completed"
            else:
                stages[name] = "incomplete"

    stages["report"] = "completed"
    return stages

def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class WebScanState:
    """Internal state for one browser-initiated scan."""

    scan_id: str
    source_directory: str
    results_directory: str
    state: str = "queued"
    message: str = "Scan queued."
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    events: list[dict[str, str]] = field(
        default_factory=list
    )
    stages: dict[str, str] = field(
        default_factory=_waiting_stages
    )
    result: dict[str, Any] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ScanService:
    """Coordinate one hardened container scan at a time."""

    def __init__(
        self,
        controller: DockerScanController,
    ) -> None:
        self.controller = controller
        self._lock = threading.Lock()
        self._scans: dict[str, WebScanState] = {}
        self._active_scan_id: str | None = None

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

        root = resolve_history_root(
            results_directory
        )
        case_directory = resolve_case_directory(
            root,
            case_id,
        )
        metadata = read_session_metadata(
            case_directory
        )
        result = load_case_result(
            case_directory,
            case_id,
        )
        created_at = metadata_string(
            metadata,
            "created_at",
            case_created_at(case_id),
        )
        updated_at = metadata_string(
            metadata,
            "updated_at",
            created_at,
        )
        source_directory = metadata_string(
            metadata,
            "source_directory",
            "",
            max_length=4096,
        )
        events = metadata_events(metadata)

        if not events:
            events = [
                {
                    "time": updated_at,
                    "message": (
                        "Loaded saved scan results."
                    ),
                }
            ]

        return {
            "scan_id": case_id,
            "source_directory": source_directory,
            "results_directory": str(root),
            "state": "completed",
            "message": "Loaded saved scan results.",
            "created_at": created_at,
            "updated_at": updated_at,
            "events": events,
            "stages": _stages_from_report(
                result["report"]
            ),
            "result": result,
            "error": None,
        }

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
        """Create a scan record and start its worker thread."""

        request = self.prepare_request(
            source_directory,
            results_directory,
        )

        with self._lock:
            if self._active_scan_id is not None:
                active = self._scans[
                    self._active_scan_id
                ]

                if active.state in _ACTIVE_STATES:
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

            if state.state not in _ACTIVE_STATES:
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
            and active.state in _ACTIVE_STATES
        ):
            self.controller.cancel()

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
            state.updated_at = _now()
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
            stage not in _SCAN_STAGE_NAMES
            or status not in _SCAN_STAGE_STATUSES
        ):
            return

        with self._lock:
            state = self._scans[scan_id]

            if state.state in _TERMINAL_STATES:
                return

            state.stages[stage] = status
            state.message = message
            state.updated_at = _now()
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
                status in _TERMINAL_STATES
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
        state.updated_at = _now()
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
                state.stages = _stages_from_report(
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