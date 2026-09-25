"""Thread-safe scan state for the local Mantha Ray web application."""

from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

from .host_scan import (
    DockerScanController,
    DockerScanRequest,
    HostScanError,
    ScanCancelled,
    validate_request,
)


_MAX_REPORT_BYTES = 8 * 1024 * 1024
_MAX_HISTORY_INDEX_BYTES = 512 * 1024
_MAX_SESSION_METADATA_BYTES = 1024 * 1024
_MAX_HISTORY_CASES = 200
_MAX_HISTORY_EVENTS = 500
_MAX_FILES_JSONL_BYTES = 32 * 1024 * 1024
_MAX_ARTIFACT_LINE_BYTES = 64 * 1024
_MAX_ARTIFACTS = 25_000
_MAX_ARTIFACT_PATH_LENGTH = 4096
_SESSION_METADATA_NAME = "web-session.json"
_CASE_ID_PATTERN = re.compile(
    r"^case-(\d{8}T\d{6}Z)-[0-9a-f]{8}$"
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


def _paths_overlap(first: Path, second: Path) -> bool:
    return (
        first == second
        or first.is_relative_to(second)
        or second.is_relative_to(first)
    )


def _read_bounded_text(
    path: Path,
    max_bytes: int = _MAX_REPORT_BYTES,
) -> str:
    if path.is_symlink() or not path.is_file():
        raise HostScanError(
            f"Required file '{path.name}' is unavailable."
        )

    if path.stat().st_size > max_bytes:
        raise HostScanError(
            f"File '{path.name}' exceeds the web limit."
        )

    return path.read_text(
        encoding="utf-8",
        errors="replace",
    )
def _optional_artifact_string(
    item: dict[str, Any],
    name: str,
    *,
    max_length: int = 512,
) -> str | None:
    value = item.get(name)

    if (
        isinstance(value, str)
        and len(value) <= max_length
    ):
        return value

    return None


def _validated_artifact_path(
    value: object,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_ARTIFACT_PATH_LENGTH
    ):
        raise HostScanError(
            "The saved artifact inventory contains "
            "an invalid relative path."
        )

    path = PurePosixPath(value)

    if (
        path.is_absolute()
        or any(
            part in {"", ".", ".."}
            for part in path.parts
        )
    ):
        raise HostScanError(
            "The saved artifact inventory contains "
            "an unsafe relative path."
        )

    return path.as_posix()


def _load_case_artifacts(
    case_directory: Path,
) -> list[dict[str, Any]]:
    """Load a bounded and sanitized files.jsonl inventory."""

    inventory_path = case_directory / "files.jsonl"

    if not inventory_path.exists():
        # Older or manually-created test cases may not have
        # an inventory file.
        return []

    contents = _read_bounded_text(
        inventory_path,
        _MAX_FILES_JSONL_BYTES,
    )
    artifacts: list[dict[str, Any]] = []

    for line_number, raw_line in enumerate(
        contents.splitlines(),
        start=1,
    ):
        if not raw_line.strip():
            continue

        if (
            len(raw_line.encode("utf-8"))
            > _MAX_ARTIFACT_LINE_BYTES
        ):
            raise HostScanError(
                "An artifact inventory entry exceeds "
                "the web limit."
            )

        if len(artifacts) >= _MAX_ARTIFACTS:
            raise HostScanError(
                "The artifact inventory exceeds "
                "the web file limit."
            )

        try:
            item = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise HostScanError(
                "The saved artifact inventory contains "
                f"invalid JSON on line {line_number}."
            ) from exc

        if not isinstance(item, dict):
            raise HostScanError(
                "The saved artifact inventory contains "
                f"an invalid entry on line {line_number}."
            )

        relative_path = _validated_artifact_path(
            item.get("relative_path")
        )

        size_value = item.get("size_bytes")
        size_bytes = (
            size_value
            if (
                isinstance(size_value, int)
                and not isinstance(size_value, bool)
                and size_value >= 0
            )
            else None
        )

        sha256 = _optional_artifact_string(
            item,
            "sha256",
            max_length=64,
        )

        if (
            sha256 is not None
            and re.fullmatch(
                r"[0-9a-fA-F]{64}",
                sha256,
            )
            is None
        ):
            sha256 = None

        evidence = item.get("evidence")
        review_flags = (
            len(evidence)
            if isinstance(evidence, list)
            else 0
        )

        artifacts.append(
            {
                "relative_path": relative_path,
                "kind": (
                    _optional_artifact_string(
                        item,
                        "kind",
                        max_length=64,
                    )
                    or "unknown"
                ),
                "detected_type": (
                    _optional_artifact_string(
                        item,
                        "detected_type",
                        max_length=256,
                    )
                ),
                "routing_class": (
                    _optional_artifact_string(
                        item,
                        "routing_class",
                        max_length=64,
                    )
                ),
                "state": (
                    _optional_artifact_string(
                        item,
                        "state",
                        max_length=64,
                    )
                ),
                "mode": (
                    _optional_artifact_string(
                        item,
                        "mode",
                        max_length=32,
                    )
                ),
                "size_bytes": size_bytes,
                "sha256": (
                    sha256.lower()
                    if sha256 is not None
                    else None
                ),
                "review_flags": review_flags,
                "error": (
                    _optional_artifact_string(
                        item,
                        "error",
                        max_length=1024,
                    )
                ),
            }
        )

    return artifacts


def _case_created_at(case_id: str) -> str:
    match = _CASE_ID_PATTERN.fullmatch(case_id)

    if match is None:
        raise HostScanError(
            "The requested case ID is invalid."
        )

    try:
        created = datetime.strptime(
            match.group(1),
            "%Y%m%dT%H%M%SZ",
        ).replace(tzinfo=UTC)
    except ValueError as exc:
        raise HostScanError(
            "The requested case ID is invalid."
        ) from exc

    return created.isoformat()


def _resolve_history_root(
    results_directory: str,
) -> Path:
    try:
        root = Path(
            results_directory
        ).expanduser().resolve(strict=True)
    except OSError as exc:
        raise HostScanError(
            "The results directory is unavailable."
        ) from exc

    if not root.is_dir():
        raise HostScanError(
            "The results path must be a directory."
        )

    if not os.access(root, os.R_OK | os.X_OK):
        raise HostScanError(
            "The results directory is not readable."
        )

    return root


def _resolve_case_directory(
    root: Path,
    case_id: str,
) -> Path:
    _case_created_at(case_id)
    candidate = root / case_id

    if candidate.is_symlink():
        raise HostScanError(
            "Symbolic-link case directories are not allowed."
        )

    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise HostScanError(
            "The requested case directory is unavailable."
        ) from exc

    if resolved.parent != root or not resolved.is_dir():
        raise HostScanError(
            "The requested case directory is unavailable."
        )

    return resolved


def _metadata_events(
    metadata: dict[str, Any],
) -> list[dict[str, str]]:
    raw_events = metadata.get("events")

    if not isinstance(raw_events, list):
        return []

    events: list[dict[str, str]] = []

    for item in raw_events[:_MAX_HISTORY_EVENTS]:
        if not isinstance(item, dict):
            continue

        time_value = item.get("time")
        message = item.get("message")

        if (
            isinstance(time_value, str)
            and isinstance(message, str)
            and len(time_value) <= 64
            and len(message) <= 4096
        ):
            events.append(
                {
                    "time": time_value,
                    "message": message,
                }
            )

    return events

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

        if _paths_overlap(source, results):
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

        requested_root = Path(
            results_directory
        ).expanduser()

        if not requested_root.exists():
            return {
                "cases": [],
                "truncated": False,
            }

        root = _resolve_history_root(
            results_directory
        )

        try:
            candidates = sorted(
                (
                    entry
                    for entry in root.iterdir()
                    if (
                        _CASE_ID_PATTERN.fullmatch(
                            entry.name
                        )
                        is not None
                        and not entry.is_symlink()
                        and entry.is_dir()
                    )
                ),
                key=lambda entry: entry.name,
                reverse=True,
            )
        except OSError as exc:
            raise HostScanError(
                "Saved cases could not be listed."
            ) from exc

        summaries: list[dict[str, Any]] = []

        for case_directory in candidates[
            :_MAX_HISTORY_CASES
        ]:
            try:
                summaries.append(
                    self._case_summary(
                        root,
                        case_directory.name,
                    )
                )
            except (
                HostScanError,
                OSError,
                json.JSONDecodeError,
            ):
                # Ignore incomplete or user-created directories;
                # they are not trustworthy scan history.
                continue

        return {
            "cases": summaries,
            "truncated": (
                len(candidates) > _MAX_HISTORY_CASES
            ),
        }

    def load_case(
        self,
        results_directory: str,
        case_id: str,
    ) -> dict[str, Any]:
        """Load one saved case as a completed scan state."""

        root = _resolve_history_root(
            results_directory
        )
        case_directory = _resolve_case_directory(
            root,
            case_id,
        )
        metadata = self._read_session_metadata(
            case_directory
        )
        result = self._load_case_result(
            case_directory,
            case_id,
        )
        created_at = self._metadata_string(
            metadata,
            "created_at",
            _case_created_at(case_id),
        )
        updated_at = self._metadata_string(
            metadata,
            "updated_at",
            created_at,
        )
        source_directory = self._metadata_string(
            metadata,
            "source_directory",
            "",
            max_length=4096,
        )
        events = _metadata_events(metadata)

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

        root = _resolve_history_root(
            results_directory
        )
        return _resolve_case_directory(
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

        root = _resolve_history_root(
            results_directory
        )
        return _resolve_case_directory(
            root,
            case_id,
        )

    def _case_summary(
        self,
        root: Path,
        case_id: str,
    ) -> dict[str, Any]:
        case_directory = _resolve_case_directory(
            root,
            case_id,
        )
        metadata = self._read_session_metadata(
            case_directory
        )
        metadata_case_id = metadata.get("case_id")

        if (
            metadata_case_id is not None
            and metadata_case_id != case_id
        ):
            raise HostScanError(
                "The saved session case ID is invalid."
            )

        for required_name in (
            "report.json",
            "report.md",
        ):
            required_path = (
                case_directory / required_name
            )

            if (
                required_path.is_symlink()
                or not required_path.is_file()
            ):
                raise HostScanError(
                    "The saved case is incomplete."
                )

        source_directory = self._metadata_string(
            metadata,
            "source_directory",
            "",
            max_length=4096,
        )
        created_at = self._metadata_string(
            metadata,
            "created_at",
            _case_created_at(case_id),
        )
        status_value = metadata.get("status")

        if not isinstance(status_value, str):
            report_path = (
                case_directory / "report.json"
            )
            report = json.loads(
                _read_bounded_text(
                    report_path,
                    _MAX_HISTORY_INDEX_BYTES,
                )
            )

            if not isinstance(report, dict):
                raise HostScanError(
                    "The saved report is invalid."
                )

            status_value = report.get("status")

        if (
            not isinstance(status_value, str)
            or not status_value
            or len(status_value) > 128
        ):
            raise HostScanError(
                "The saved report status is invalid."
            )

        label = (
            Path(source_directory).name
            if source_directory
            else case_id
        )

        return {
            "case_id": case_id,
            "status": status_value,
            "created_at": created_at,
            "source_directory": (
                source_directory or None
            ),
            "label": label,
        }

    @staticmethod
    def _metadata_string(
        metadata: dict[str, Any],
        name: str,
        default: str,
        *,
        max_length: int = 128,
    ) -> str:
        value = metadata.get(name)

        if (
            isinstance(value, str)
            and 0 < len(value) <= max_length
        ):
            return value

        return default

    @staticmethod
    def _read_session_metadata(
        case_directory: Path,
    ) -> dict[str, Any]:
        path = case_directory / _SESSION_METADATA_NAME

        if not path.exists():
            return {}

        metadata = json.loads(
            _read_bounded_text(
                path,
                _MAX_SESSION_METADATA_BYTES,
            )
        )

        if not isinstance(metadata, dict):
            raise HostScanError(
                "The saved session metadata is invalid."
            )

        if metadata.get("schema_version") != 1:
            raise HostScanError(
                "The saved session metadata version is unsupported."
            )

        return metadata

    @staticmethod
    def _load_case_result(
        case_directory: Path,
        case_id: str,
    ) -> dict[str, Any]:
        report_json_path = (
            case_directory / "report.json"
        )
        report_markdown_path = (
            case_directory / "report.md"
        )
        report = json.loads(
            _read_bounded_text(report_json_path)
        )

        if not isinstance(report, dict):
            raise HostScanError(
                "The saved JSON report is invalid."
            )

        reported_case_id = report.get("case_id")

        if reported_case_id != case_id:
            raise HostScanError(
                "The saved report case ID does not match its directory."
            )

        status_value = report.get("status")

        if (
            not isinstance(status_value, str)
            or not status_value
            or len(status_value) > 128
        ):
            raise HostScanError(
                "The saved report status is invalid."
            )

        return {
            "case_id": case_id,
            "status": status_value,
            "case_directory": str(case_directory),
            "report_path": str(report_markdown_path),
            "report": report,
            "report_markdown": _read_bounded_text(
                report_markdown_path
            ),
            "artifacts": _load_case_artifacts(
                case_directory
            ),
        }

    def _persist_session_metadata(
        self,
        state: dict[str, Any],
    ) -> None:
        result = state.get("result")

        if not isinstance(result, dict):
            return

        case_value = result.get("case_directory")
        status_value = result.get("status")

        if (
            not isinstance(case_value, str)
            or not isinstance(status_value, str)
        ):
            return

        case_directory = Path(case_value)
        metadata_path = (
            case_directory / _SESSION_METADATA_NAME
        )
        temporary_path = (
            case_directory
            / f".{_SESSION_METADATA_NAME}.{uuid4().hex}.tmp"
        )

        metadata = {
            "schema_version": 1,
            "case_id": result.get("case_id"),
            "status": status_value,
            "source_directory": state.get(
                "source_directory"
            ),
            "created_at": state.get("created_at"),
            "updated_at": state.get("updated_at"),
            "events": state.get("events", [])[
                -_MAX_HISTORY_EVENTS:
            ],
            "stages": state.get("stages", {}),
        }

        temporary_path.write_text(
            json.dumps(
                metadata,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        temporary_path.replace(metadata_path)

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
                _read_bounded_text(report_json_path)
            )

            if not isinstance(report_json, dict):
                raise HostScanError(
                    "The generated JSON report is invalid."
                )

            report_markdown = _read_bounded_text(
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
                "artifacts": _load_case_artifacts(
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
                self._persist_session_metadata(
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
