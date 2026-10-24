"""Public coordinator used by the web API.

ScanService validates browser requests and delegates: saved-case access
to the history module and live scans to ScanRuntime.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..host_scan import (
    DockerScanController,
    DockerScanRequest,
    HostScanError,
    validate_request,
)
from ..resource_profiles import (
    DEFAULT_PRESET,
    MAX_OVERRIDE_KEYS,
    ResourceProfile,
    ResourceProfileError,
    catalog,
    check_capacity,
    profile_summary,
    resolve_profile,
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

    def resolve_resources(
        self,
        resource_profile: str | None = None,
        resource_overrides: Mapping[str, object] | None = None,
    ) -> ResourceProfile:
        """Resolve a client's preset choice and overrides, strictly."""

        if (
            resource_overrides is not None
            and len(resource_overrides) > MAX_OVERRIDE_KEYS
        ):
            raise HostScanError(
                "Too many resource settings were supplied."
            )

        try:
            return resolve_profile(
                resource_profile or DEFAULT_PRESET,
                resource_overrides,
            )
        except ResourceProfileError as exc:
            raise HostScanError(
                f"Invalid resource settings: {exc}"
            ) from exc

    def docker_capacity(self) -> tuple[float, int] | None:
        """Return Docker's CPUs and memory, or None if unknown."""

        probe = getattr(self.controller, "docker_capacity", None)
        if probe is None:
            return None
        try:
            return probe()
        except HostScanError:
            return None

    def rule_packs(self) -> dict[str, Any]:
        """The signed bundle in use and your own rule files, for the UI."""

        from ..packs import local, store

        try:
            info = store.status()
        except store.PackInstallError as exc:
            info = {"installed": None, "error": str(exc)}
        installed = info.get("installed")
        return {
            "bundle": (
                {
                    "version": installed["version"],
                    "verified": installed["verified"],
                    "created_at": installed.get("created_at"),
                    "stale": installed.get("stale", False),
                    "rules": sum(p["rules"] for p in installed.get("packs", []) if p["loaded"]),
                }
                if installed
                else None
            ),
            "local": local.list_local(),
            "max_local": local.MAX_LOCAL_PACKS,
            "error": info.get("error"),
        }

    def add_local_rules(
        self,
        filename: str,
        content: str,
        severity: str,
    ) -> dict[str, Any]:
        """Add one uploaded .yar file as your own rules, once it compiles."""

        from ..packs import local, store
        from ..packs.check import container_compile_check

        if self.controller is None:
            raise HostScanError("Rules can't be checked without the container engine.")
        engine = getattr(self.controller, "engine", "docker")
        image = getattr(self.controller, "image", "static-triage:core")
        try:
            added = local.add_local(
                content,
                source=filename,
                severity=severity,
                compile_check=lambda staging: container_compile_check(
                    staging, image=image, engine=engine, target="/packs-local",
                ),
            )
        except store.PackInstallError as exc:
            raise HostScanError(str(exc)) from exc
        return {"added": added, **self.rule_packs()}

    def remove_local_rules(self, name: str) -> dict[str, Any]:
        from ..packs import local, store

        try:
            local.remove_local(name)
        except store.PackInstallError as exc:
            raise HostScanError(str(exc)) from exc
        return self.rule_packs()

    def resource_options(self) -> dict[str, Any]:
        """Presets, editable fields, and Docker's capacity for the UI."""

        capacity = self.docker_capacity()
        return {
            "catalog": catalog(),
            "capacity": (
                None
                if capacity is None
                else {
                    "cpus": capacity[0],
                    "memory_bytes": capacity[1],
                }
            ),
        }

    def validate_resources(
        self,
        resource_profile: str | None = None,
        resource_overrides: Mapping[str, object] | None = None,
    ) -> dict[str, Any]:
        """Check a selection without starting a scan.

        Problems are tied to fields so the UI can show each one next to
        its input. Capacity is checked against Docker, not the host.
        """

        if (
            resource_overrides is not None
            and len(resource_overrides) > MAX_OVERRIDE_KEYS
        ):
            return {
                "ok": False,
                "profile": None,
                "problems": [{
                    "field": None,
                    "message": "Too many resource settings were supplied.",
                }],
                "warnings": [],
            }

        try:
            profile = resolve_profile(
                resource_profile or DEFAULT_PRESET,
                resource_overrides,
            )
        except ResourceProfileError as exc:
            return {
                "ok": False,
                "profile": None,
                "problems": [
                    {"field": field, "message": message}
                    for field, message in exc.problems
                ],
                "warnings": [],
            }

        capacity = self.docker_capacity()
        if capacity is None:
            warnings = [
                "Docker did not report its capacity, so these limits "
                "could not be checked against it."
            ]
        else:
            try:
                warnings = check_capacity(
                    profile,
                    cpus_available=capacity[0],
                    memory_bytes_available=capacity[1],
                )
            except ResourceProfileError as exc:
                return {
                    "ok": False,
                    "profile": profile_summary(profile),
                    "problems": [
                        {"field": field, "message": message}
                        for field, message in exc.problems
                    ],
                    "warnings": [],
                }

        return {
            "ok": True,
            "profile": profile_summary(profile),
            "problems": [],
            "warnings": warnings,
        }

    def prepare_request(
        self,
        source_directory: str,
        results_directory: str,
        resource_profile: str | None = None,
        resource_overrides: Mapping[str, object] | None = None,
    ) -> DockerScanRequest:
        """Validate paths before creating the results directory."""

        profile = self.resolve_resources(
            resource_profile,
            resource_overrides,
        )

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
                resource_profile=profile,
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
        resource_profile: str | None = None,
        resource_overrides: Mapping[str, object] | None = None,
    ) -> dict[str, Any]:
        """Validate the request, then start a background scan."""

        request = self.prepare_request(
            source_directory,
            results_directory,
            resource_profile,
            resource_overrides,
        )
        return self._runtime.start(request)

    def get(
        self,
        scan_id: str,
    ) -> dict[str, Any]:
        """Return a detached representation of a scan."""

        return self._runtime.get(scan_id)

    def stop(
        self,
        scan_id: str,
    ) -> dict[str, Any]:
        """Stop an active scan and keep a report of finished work."""

        return self._runtime.stop(scan_id)

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