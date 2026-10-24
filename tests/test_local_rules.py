from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from static_triage.packs import local
from static_triage.packs.contract import validate_pack
from static_triage.packs.store import PackInstallError
from static_triage.web_service import ScanService
from static_triage.yara_scan import compile_rules, run_yara_stage

from test_packs import write_bundle
from test_yara_stage import fake_yr, install, real_yr, sample

try:
    from fastapi.testclient import TestClient

    from static_triage.web_api import create_app
except (ImportError, RuntimeError):  # pragma: no cover - extras missing
    TestClient = None

MY_RULES = """
import "pe"
private rule Helper { condition: uint16(0) == 0x5A4D }
rule My_Miner_Config { strings: $a = "stratum+tcp://" condition: $a }
rule My_Fake_Launcher { condition: Helper and filename == "Launcher.exe" }
"""


class AddLocalTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.home = Path(self._temporary.name) / "home"
        self.checked: list[Path] = []

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def add(self, text: str = MY_RULES, **kwargs) -> dict:
        kwargs.setdefault("source", "My Rules (v2).yar")
        return local.add_local(
            text,
            compile_check=lambda staging: self.checked.append(
                sorted(p.name for p in staging.iterdir())
            ) or {"ok": True},
            home=self.home, **kwargs,
        )

    def test_rule_file_becomes_a_valid_local_pack(self) -> None:
        added = self.add()
        self.assertEqual(added["name"], "my-rules-v2")
        self.assertEqual(added["rules"], 2)  # the private helper isn't listed
        self.assertEqual(added["severity"], "suspicious")
        self.assertEqual(added["externals"], ["filename"])
        pack = validate_pack(self.home / "local" / "my-rules-v2", local=True)
        self.assertEqual(pack.id, "local:my-rules-v2")
        self.assertTrue(pack.is_local)
        self.assertEqual(pack.severity("rules", "My_Miner_Config"), "suspicious")
        # The compile check saw the new pack on its own, in a staging folder.
        self.assertEqual(self.checked[0], ["my-rules-v2"])
        self.assertFalse(any(p.name.startswith(".") for p in (self.home / "local").iterdir()))

    def test_list_and_remove(self) -> None:
        self.add(severity="threat")
        self.add(source="other.yara", severity="info")
        listed = local.list_local(self.home)
        self.assertEqual([(p["name"], p["severity"]) for p in listed],
                         [("my-rules-v2", "threat"), ("other", "info")])
        local.remove_local("other", self.home)
        self.assertEqual([p["name"] for p in local.list_local(self.home)], ["my-rules-v2"])
        for bad in ("other", "../home", "local", ".staging-x"):
            with self.subTest(name=bad), self.assertRaises(PackInstallError):
                local.remove_local(bad, self.home)

    def test_refusals(self) -> None:
        cases = {
            "no rules": "private rule Only { condition: true }",
            "include": 'include "other.yar"\nrule A { condition: true }',
            "bad severity": MY_RULES,
        }
        for label, text in cases.items():
            with self.subTest(case=label), self.assertRaises(PackInstallError):
                self.add(text, severity="critical" if label == "bad severity" else "suspicious")
        self.assertEqual(local.list_local(self.home), [])

    def test_same_name_needs_replace(self) -> None:
        self.add()
        with self.assertRaisesRegex(PackInstallError, "already have"):
            self.add()
        self.add("rule Replaced { condition: true }", replace=True)
        self.assertEqual(local.list_local(self.home)[0]["rule_names"], ["Replaced"])

    def test_failed_check_keeps_nothing(self) -> None:
        def failing(staging: Path) -> dict:
            raise PackInstallError("the rules don't compile: line 3: syntax error")

        with self.assertRaisesRegex(PackInstallError, "syntax error"):
            local.add_local(MY_RULES, source="x.yar", compile_check=failing, home=self.home)
        self.assertEqual(list((self.home / "local").iterdir()), [])

    def test_limit(self) -> None:
        with patch.object(local, "MAX_LOCAL_PACKS", 1):
            self.add()
            with self.assertRaisesRegex(PackInstallError, "up to 1"):
                self.add(source="second.yar")

    def test_names(self) -> None:
        self.assertEqual(local.pack_name("Steam Stealers.YAR"), "steam-stealers")
        self.assertEqual(local.pack_name("___.yar"), "rules")
        self.assertEqual(local.pack_name("-x.yar"), "x")
        self.assertLessEqual(len(local.pack_name("a" * 100 + ".yar")), 40)


class LocalScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        self.home = self.root / "home"
        self.yr = fake_yr(self.root)
        self.scan_root = self.root / "sample"
        self.scan_root.mkdir()

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def add(self, severity: str = "suspicious") -> None:
        local.add_local(MY_RULES, source="mine.yar", severity=severity, home=self.home)

    def test_local_rules_alone(self) -> None:
        self.add("threat")
        entries = sample(self.scan_root, {"config.json": b"MATCH:local.mine.rules:My_Miner_Config "})
        result = run_yara_stage(
            entries, self.scan_root, executable=self.yr, app_version="0.1.0",
            packs_root=self.root / "no-bundle", local_root=self.home / "local",
        )
        self.assertEqual(result.status, "completed")
        self.assertIsNone(result.bundle)
        match = result.results[0].matches[0]
        self.assertEqual((match.pack, match.namespace, match.severity),
                         ("local:mine", "rules", "threat"))
        self.assertTrue(result.packs[0]["local"])

    def test_local_beside_bundle_and_broken_bundle(self) -> None:
        self.add()
        packs = install(self.root / "packs")
        work = self.root / "work"
        work.mkdir()
        rules, _ = compile_rules(packs, work, executable=self.yr, app_version="0.1.0",
                                 local_root=self.home / "local")
        self.assertEqual([p.id for p in rules.packs], ["core-threats", "local:mine"])
        self.assertIn("local.mine.rules", rules.by_namespace)
        # A broken bundle doesn't stop your own rules; it's reported instead.
        (packs / "bundle" / "manifest.json").write_text("{}")
        rules, _ = compile_rules(packs, work, executable=self.yr, app_version="0.1.0",
                                 local_root=self.home / "local")
        self.assertEqual([p.id for p in rules.packs], ["local:mine"])
        self.assertEqual(rules.skipped[0]["id"], "bundle")

    def test_invalid_local_pack_is_left_out(self) -> None:
        self.add()
        (self.home / "local" / "mine" / "pack.json").write_text("{}")
        write_bundle(self.root / "packs" / "bundle")
        work = self.root / "work"
        work.mkdir()
        rules, _ = compile_rules(self.root / "packs", work, executable=self.yr,
                                 app_version="0.1.0", local_root=self.home / "local")
        self.assertEqual([p.id for p in rules.packs], ["core-threats"])
        self.assertTrue(rules.skipped[0]["reason"].startswith("invalid"))

    @unittest.skipUnless(real_yr(), "YARA-X (yr) is not installed; set MANTHA_RAY_YR to run")
    def test_real_yr_with_imports_and_externals(self) -> None:
        self.add("threat")
        entries = sample(self.scan_root, {
            "pool.cfg": b'{"url": "stratum+tcp://pool.example:3333"}',
            "Launcher.exe": b"MZ\x00\x00",
            "launcher2.exe": b"MZ\x00\x00",
        })
        result = run_yara_stage(
            entries, self.scan_root, executable=real_yr(), app_version="0.1.0",
            packs_root=self.root / "no-bundle", local_root=self.home / "local",
        )
        self.assertEqual(result.status, "completed", result.error)
        found = {(r.relative_path, m.rule) for r in result.results for m in r.matches}
        self.assertEqual(found, {("pool.cfg", "My_Miner_Config"), ("Launcher.exe", "My_Fake_Launcher")})


class FakeController:
    image = "static-triage:core"
    engine = "docker"


@unittest.skipIf(TestClient is None, "fastapi and httpx are required for API tests")
class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        root = Path(self._temporary.name)
        self.env = patch.dict(os.environ, {"MANTHA_RAY_PACKS_HOME": str(root / "home")})
        self.env.start()
        self.check = patch(
            "static_triage.packs.check.container_compile_check",
            return_value={"ok": True},
        )
        self.checked = self.check.start()
        static = root / "static"
        static.mkdir()
        (static / "index.html").write_text("<!doctype html>")
        app = create_app(ScanService(FakeController()), "t", static, "http://127.0.0.1:8765")
        self.client = TestClient(app, base_url="http://127.0.0.1")
        self.client.post("/api/session", headers={"X-Mantha-Ray-Token": "t"})

    def tearDown(self) -> None:
        self.check.stop()
        self.env.stop()
        self._temporary.cleanup()

    def test_upload_list_remove(self) -> None:
        body = self.client.get("/api/packs").json()
        self.assertEqual((body["bundle"], body["local"]), (None, []))
        response = self.client.post("/api/packs/local", json={
            "filename": "mine.yar", "content": MY_RULES, "severity": "threat",
        })
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["added"]["name"], "mine")
        self.assertEqual(body["local"][0]["severity"], "threat")
        self.assertEqual(self.checked.call_args.kwargs["target"], "/packs-local")
        response = self.client.delete("/api/packs/local/mine")
        self.assertEqual(response.json()["local"], [])

    def test_bad_uploads(self) -> None:
        cases = [
            {"filename": "x.yar", "content": "private rule A { condition: true }"},
            {"filename": "x.yar", "content": MY_RULES, "severity": "critical"},
            {"filename": "x.yar", "content": ""},
        ]
        for payload in cases:
            with self.subTest(payload=payload["content"][:20]):
                self.assertIn(self.client.post("/api/packs/local", json=payload).status_code,
                              (400, 422))
        self.assertIn(self.client.delete("/api/packs/local/..%2Fx").status_code, (400, 404, 405))
        self.assertEqual(self.client.delete("/api/packs/local/nope").status_code, 400)

    def test_needs_session(self) -> None:
        fresh = TestClient(self.client.app, base_url="http://127.0.0.1")
        self.assertEqual(fresh.get("/api/packs").status_code, 401)


if __name__ == "__main__":
    unittest.main()
