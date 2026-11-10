from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from static_triage.web import state as state_module
from static_triage.web.runtime import ScanRuntime
from static_triage.web.state import WebScanState

try:
    from fastapi.testclient import TestClient

    from static_triage.web_api import create_app
    from static_triage.web_service import ScanService
except (ImportError, RuntimeError):  # pragma: no cover - extras missing
    TestClient = None


def runtime_with_scan() -> ScanRuntime:
    runtime = ScanRuntime(controller=None)  # type: ignore[arg-type]
    runtime._scans["scan-1"] = WebScanState(
        scan_id="scan-1", source_directory="/s", results_directory="/r", state="running",
    )
    return runtime


class ActivityLogTests(unittest.TestCase):
    def test_events_are_numbered_and_capped(self) -> None:
        state = WebScanState(scan_id="s", source_directory="/s", results_directory="/r")
        with patch.object(state_module, "MAX_EVENTS", 5):
            for number in range(1, 13):
                state.add_event("t", f"message {number}")
        self.assertEqual(state.event_count, 12)
        self.assertEqual([e["seq"] for e in state.events], [8, 9, 10, 11, 12])
        data = state.to_dict()
        self.assertEqual((data["event_count"], len(data["events"])), (12, 5))

    def test_since_returns_only_new_events(self) -> None:
        runtime = runtime_with_scan()
        for number in range(1, 5):
            runtime._stage("scan-1", "capa", "running", f"capa {number}/4 started: f{number}.exe (1 KB)")
        everything = runtime.get("scan-1")
        self.assertEqual([e["seq"] for e in everything["events"]], [1, 2, 3, 4])
        newer = runtime.get("scan-1", since=2)
        self.assertEqual([e["message"] for e in newer["events"]],
                         ["capa 3/4 started: f3.exe (1 KB)", "capa 4/4 started: f4.exe (1 KB)"])
        self.assertEqual(runtime.get("scan-1", since=4)["events"], [])
        # Asking for a copy never changes the log itself.
        self.assertEqual(len(runtime.get("scan-1")["events"]), 4)

    def test_queues_are_sent_only_when_changed(self) -> None:
        runtime = runtime_with_scan()
        items = [{"position": 1, "path": "a.exe", "size": "1 MB", "copies": 0, "mode": ""}]
        runtime._queue("scan-1", "capa", 0, 1, items)
        first = runtime.get("scan-1", queues_since=0)
        version = first["queues_version"]
        self.assertEqual(first["queues"]["capa"]["items"][0]["status"], "waiting")
        self.assertIsNone(runtime.get("scan-1", queues_since=version)["queues"])
        runtime._stage("scan-1", "capa", "running", "capa 1/1 started: a.exe (1 MB)")
        changed = runtime.get("scan-1", queues_since=version)
        self.assertEqual(changed["queues"]["capa"]["items"][0]["status"], "running")
        self.assertGreater(changed["queues_version"], version)
        # A stage without a queue doesn't count as a queue change.
        runtime._stage("scan-1", "yara", "running", "YARA-X is matching rule packs...")
        self.assertIsNone(runtime.get("scan-1", queues_since=changed["queues_version"])["queues"])
        # Without queues_since, everything is sent.
        self.assertIsNotNone(runtime.get("scan-1")["queues"])

    def test_a_long_scan_stays_small(self) -> None:
        runtime = runtime_with_scan()
        for number in range(50_000):
            runtime._stage("scan-1", "yara", "running", f"YARA-X matched rule {number}")
        data = runtime.get("scan-1")
        self.assertEqual(data["event_count"], 50_000)
        self.assertEqual(len(data["events"]), state_module.MAX_EVENTS)
        self.assertEqual(data["events"][-1]["seq"], 50_000)


class FakeController:
    image = "static-triage:core"
    engine = "docker"


@unittest.skipIf(TestClient is None, "fastapi and httpx are required for API tests")
class ApiTests(unittest.TestCase):
    def test_since_parameter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            static = Path(temporary)
            (static / "index.html").write_text("<!doctype html>")
            service = ScanService(FakeController())
            service._runtime._scans["scan-1"] = WebScanState(
                scan_id="scan-1", source_directory="/s", results_directory="/r", state="running",
            )
            for number in range(3):
                service._runtime._stage("scan-1", "yara", "running", f"m{number}")
            client = TestClient(create_app(service, "t", static, "http://127.0.0.1:8765"),
                                base_url="http://127.0.0.1")
            client.post("/api/session", headers={"X-Mantha-Ray-Token": "t"})
            body = client.get("/api/scans/scan-1", params={"since": 2}).json()
            self.assertEqual([e["message"] for e in body["events"]], ["m2"])
            self.assertEqual(body["event_count"], 3)
            self.assertEqual(len(client.get("/api/scans/scan-1").json()["events"]), 3)
            self.assertEqual(client.get("/api/scans/scan-1", params={"since": -1}).status_code, 422)


if __name__ == "__main__":
    unittest.main()
