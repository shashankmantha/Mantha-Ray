from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from static_triage.host_scan import HostScanError
from static_triage.resource_profiles import PRESETS, resolve_profile
from static_triage.web_service import ScanService

try:  # The HTTP tests need the web extra plus httpx.
    from fastapi.testclient import TestClient

    from static_triage.web_api import create_app
except (ImportError, RuntimeError):  # pragma: no cover - extras missing
    TestClient = None

GIB = 1024**3
TOKEN = "test-token"
ORIGIN = "http://127.0.0.1:8765"


class RecordingController:
    """Captures the request a scan was started with."""

    image = "static-triage:core"

    def __init__(self, capacity=(8.0, 16 * GIB)) -> None:
        self.capacity = capacity
        self.requests = []

    def preflight(self) -> str:
        return "test"

    def docker_capacity(self):
        if isinstance(self.capacity, Exception):
            raise self.capacity
        return self.capacity

    def scan(self, request, on_status=None, on_progress=None, on_queue=None):
        self.requests.append(request)
        raise HostScanError("stop here")

    def cancel(self) -> None:
        pass


class LegacyController:
    """A controller without docker_capacity, like the test fakes."""

    image = "static-triage:core"

    def preflight(self) -> str:
        return "test"


def _wait(service, scan_id):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        state = service.get(scan_id)
        if state["state"] in {"completed", "failed", "cancelled"}:
            return state
        time.sleep(0.01)
    raise AssertionError("scan did not finish")


class ServiceResourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name)
        self.source = base / "source"
        self.results = base / "results"
        self.source.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_default_start_uses_balanced(self) -> None:
        controller = RecordingController()
        service = ScanService(controller)
        state = service.start(str(self.source), str(self.results))
        _wait(service, state["scan_id"])
        self.assertEqual(
            controller.requests[0].resource_profile,
            resolve_profile("balanced"),
        )
        self.assertEqual(state["resource_profile"]["name"], "balanced")

    def test_preset_and_overrides_reach_the_controller(self) -> None:
        controller = RecordingController()
        service = ScanService(controller)
        state = service.start(
            str(self.source),
            str(self.results),
            "high",
            {"capa_file_timeout_seconds": 150},
        )
        _wait(service, state["scan_id"])
        profile = controller.requests[0].resource_profile
        self.assertEqual(profile.name, "custom")
        self.assertEqual(profile.base, "high")
        self.assertEqual(profile.capa_file_timeout_seconds, 150)
        self.assertEqual(
            state["resource_profile"]["changed"],
            {"capa_file_timeout_seconds": 150},
        )

    def test_invalid_selection_rejected_before_scanning(self) -> None:
        controller = RecordingController()
        service = ScanService(controller)
        for name, overrides in (
            ("turbo", None),
            ("balanced", {"privileged": 1}),
            ("balanced", {"cpus": "4"}),
            ("balanced", {"memory_mib": True}),
            ("balanced", {f"k{i}": 1 for i in range(100)}),
        ):
            with self.subTest(name=name, overrides=overrides):
                with self.assertRaises(HostScanError):
                    service.start(
                        str(self.source),
                        str(self.results),
                        name,
                        overrides,
                    )
        self.assertEqual(controller.requests, [])

    def test_resource_options(self) -> None:
        options = ScanService(RecordingController()).resource_options()
        self.assertEqual(options["catalog"]["default"], "balanced")
        self.assertEqual(
            set(options["catalog"]["presets"]),
            set(PRESETS),
        )
        self.assertEqual(
            options["capacity"],
            {"cpus": 8.0, "memory_bytes": 16 * GIB},
        )

    def test_capacity_unknown_is_none(self) -> None:
        for controller in (
            LegacyController(),
            RecordingController(capacity=None),
            RecordingController(capacity=HostScanError("no docker")),
        ):
            with self.subTest(controller=controller):
                self.assertIsNone(
                    ScanService(controller).resource_options()["capacity"]
                )

    def test_validate_ok_with_summary(self) -> None:
        result = ScanService(RecordingController()).validate_resources(
            "balanced",
            {"cpus": 3},
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["profile"]["name"], "custom")
        self.assertEqual(result["profile"]["changed"], {"cpus": 3})
        self.assertEqual(result["problems"], [])

    def test_validate_reports_problems_by_field(self) -> None:
        result = ScanService(RecordingController()).validate_resources(
            "balanced",
            {"tmp_mib": 4096},
        )
        self.assertFalse(result["ok"])
        self.assertEqual(
            [problem["field"] for problem in result["problems"]],
            ["tmp_mib"],
        )

    def test_validate_checks_docker_capacity(self) -> None:
        small = ScanService(RecordingController(capacity=(2.0, 6 * GIB)))
        result = small.validate_resources("high")
        self.assertFalse(result["ok"])
        self.assertEqual(
            {problem["field"] for problem in result["problems"]},
            {"cpus", "memory_mib"},
        )

        tight = ScanService(RecordingController(capacity=(8.0, 5 * GIB)))
        result = tight.validate_resources("balanced")
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["warnings"]), 1)

    def test_validate_warns_when_capacity_unknown(self) -> None:
        result = ScanService(LegacyController()).validate_resources()
        self.assertTrue(result["ok"])
        self.assertIn("could not be checked", result["warnings"][0])


@unittest.skipIf(
    TestClient is None,
    "fastapi and httpx are required for API tests",
)
class ApiResourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        static = self.base / "static"
        static.mkdir()
        (static / "index.html").write_text("<!doctype html>")
        self.controller = RecordingController()
        self.service = ScanService(self.controller)
        app = create_app(self.service, TOKEN, static, ORIGIN)
        self.client = TestClient(app, base_url="http://127.0.0.1")
        response = self.client.post(
            "/api/session",
            headers={"X-Mantha-Ray-Token": TOKEN, "Origin": ORIGIN},
        )
        self.assertEqual(response.status_code, 200)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_config_includes_resource_options(self) -> None:
        body = self.client.get("/api/config").json()
        self.assertIn("default_results_directory", body)
        options = body["resource_profiles"]
        self.assertEqual(options["catalog"]["default"], "balanced")
        self.assertIn("cpus", options["catalog"]["fields"])

    def test_validate_endpoint(self) -> None:
        response = self.client.post(
            "/api/resource-profiles/validate",
            json={
                "resource_profile": "balanced",
                "resource_overrides": {"host_timeout_seconds": 3600},
            },
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertFalse(body["ok"])
        self.assertEqual(
            body["problems"][0]["field"],
            "host_timeout_seconds",
        )

    def test_validate_does_not_coerce_types(self) -> None:
        body = self.client.post(
            "/api/resource-profiles/validate",
            json={
                "resource_profile": "balanced",
                "resource_overrides": {"cpus": "4", "memory_mib": True},
            },
        ).json()
        self.assertFalse(body["ok"])
        self.assertEqual(
            {problem["field"] for problem in body["problems"]},
            {"cpus", "memory_mib"},
        )

    def test_validate_requires_session(self) -> None:
        fresh = TestClient(self.client.app, base_url="http://127.0.0.1")
        response = fresh.post("/api/resource-profiles/validate", json={})
        self.assertEqual(response.status_code, 401)

    def test_start_with_invalid_profile_is_400(self) -> None:
        source = self.base / "source"
        source.mkdir()
        response = self.client.post(
            "/api/scans",
            json={
                "source_directory": str(source),
                "results_directory": str(self.base / "results"),
                "resource_profile": "turbo",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid resource settings", response.json()["detail"])
        self.assertEqual(self.controller.requests, [])

    def test_start_without_profile_still_works(self) -> None:
        source = self.base / "source"
        source.mkdir()
        response = self.client.post(
            "/api/scans",
            json={
                "source_directory": str(source),
                "results_directory": str(self.base / "results"),
            },
        )
        self.assertEqual(response.status_code, 202)
        _wait(self.service, response.json()["scan_id"])
        self.assertEqual(
            self.controller.requests[0].resource_profile.name,
            "balanced",
        )

    def test_start_with_custom_profile(self) -> None:
        source = self.base / "source"
        source.mkdir()
        response = self.client.post(
            "/api/scans",
            json={
                "source_directory": str(source),
                "results_directory": str(self.base / "results"),
                "resource_profile": "constrained",
                "resource_overrides": {"cpus": 1.5},
            },
        )
        self.assertEqual(response.status_code, 202)
        _wait(self.service, response.json()["scan_id"])
        profile = self.controller.requests[0].resource_profile
        self.assertEqual((profile.name, profile.base, profile.cpus),
                         ("custom", "constrained", 1.5))


if __name__ == "__main__":
    unittest.main()