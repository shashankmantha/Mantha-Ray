from __future__ import annotations

import base64
import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from static_triage.packs import store, update
from static_triage.packs.store import PackInstallError

from test_packs import FIXTURES, HAVE_CRYPTO, VERSION, public_key

TARBALL = f"mantha-packs-{VERSION}.tar.gz"
API = "https://api.github.com/repos/shashankmantha/mantha-packs/releases/latest"
DOWNLOAD = f"https://github.com/shashankmantha/mantha-packs/releases/download/v{VERSION}/"


def tarball_bytes() -> bytes:
    return base64.b64decode((FIXTURES / f"{TARBALL}.b64").read_text())


def signature_bytes() -> bytes:
    return (FIXTURES / f"{TARBALL}.minisig").read_bytes()


def release_json(version: str = VERSION, **changes) -> dict:
    name = f"mantha-packs-{version}.tar.gz"
    payload = {
        "tag_name": f"v{version}",
        "html_url": f"https://github.com/shashankmantha/mantha-packs/releases/tag/v{version}",
        "assets": [
            {"name": name, "size": 32000, "browser_download_url": DOWNLOAD + name},
            {"name": name + ".minisig", "size": 364, "browser_download_url": DOWNLOAD + name + ".minisig"},
            {"name": "RELEASE_NOTES.md", "browser_download_url": DOWNLOAD + "RELEASE_NOTES.md"},
        ],
    }
    payload.update(changes)
    return payload


class FakeResponse(io.BytesIO):
    def __init__(self, data: bytes, url: str) -> None:
        super().__init__(data)
        self._url = url

    def geturl(self) -> str:
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *args) -> None:
        self.close()


class FakeGitHub:
    """Serves a release and its files; records what was requested."""

    def __init__(self, release: dict | None = None, files: dict[str, bytes] | None = None,
                 redirect: dict[str, str] | None = None) -> None:
        self.release = release if release is not None else release_json()
        self.files = files if files is not None else {
            DOWNLOAD + TARBALL: tarball_bytes(),
            DOWNLOAD + TARBALL + ".minisig": signature_bytes(),
        }
        self.redirect = redirect or {}
        self.requested: list[str] = []

    def __call__(self, request, timeout):
        url = request.full_url
        self.requested.append(url)
        if url == API:
            if self.release == 404:
                raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
            return FakeResponse(json.dumps(self.release).encode(), url)
        if url in self.files:
            return FakeResponse(self.files[url], self.redirect.get(url, url))
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography is not installed")
class UpdateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.home = Path(self._temporary.name) / "home"
        self.checked: list[Path] = []
        os.environ.pop("MANTHA_RAY_PACKS_REPO", None)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def run_update(self, github: FakeGitHub):
        return update.update(
            home=self.home, opener=github, public_key_text=public_key(),
            compile_check=lambda staging: self.checked.append(staging) or {"ok": True},
        )

    def test_installs_latest_signed_release(self) -> None:
        github = FakeGitHub()
        status, installed = self.run_update(github)
        self.assertTrue(status.update_available)
        self.assertEqual((installed.version, installed.verified), (VERSION, True))
        self.assertEqual(len(self.checked), 1)  # the compile check ran
        self.assertEqual(store.status(self.home)["installed"]["version"], VERSION)
        # Downloads are cleaned up.
        self.assertEqual(list((self.home / "downloads").iterdir()), [])
        # Running again does nothing and downloads nothing.
        github = FakeGitHub()
        status, installed = self.run_update(github)
        self.assertIsNone(installed)
        self.assertFalse(status.update_available)
        self.assertEqual(github.requested, [API])

    def test_signed_release_replaces_unsigned_install_of_same_version(self) -> None:
        state = {"current": None, "highest_signed": None, "history": []}
        self.home.mkdir(parents=True)
        (self.home / "state.json").write_text(json.dumps(state))
        with patch.object(update, "current", return_value=store.Installed(
            VERSION, False, self.home, "", None,
        )):
            status, _ = update.check(home=self.home, opener=FakeGitHub())
        self.assertTrue(status.update_available)

    def test_older_release_is_refused_without_downloading(self) -> None:
        self.home.mkdir(parents=True)
        (self.home / "state.json").write_text(json.dumps(
            {"current": None, "highest_signed": "2026.11.1.1", "history": []}
        ))
        github = FakeGitHub()
        with self.assertRaisesRegex(PackInstallError, "older than a bundle already installed"):
            self.run_update(github)
        self.assertEqual(github.requested, [API])

    def test_tampered_download_is_rejected_and_nothing_changes(self) -> None:
        data = bytearray(tarball_bytes())
        data[500] ^= 1
        github = FakeGitHub(files={
            DOWNLOAD + TARBALL: bytes(data),
            DOWNLOAD + TARBALL + ".minisig": signature_bytes(),
        })
        with self.assertRaisesRegex(PackInstallError, "signature"):
            self.run_update(github)
        self.assertIsNone(store.current_install_dir(self.home))
        self.assertEqual(list((self.home / "downloads").iterdir()), [])

    def test_bad_releases(self) -> None:
        name = TARBALL
        cases = {
            "no release": (404, "no release found"),
            "no assets": (release_json(assets=[]), "exactly one"),
            "missing signature": (release_json(assets=[
                {"name": name, "browser_download_url": DOWNLOAD + name}]), "exactly one"),
            "two bundles": (release_json(assets=release_json()["assets"]
                                         + release_json("2026.10.24.2")["assets"]), "exactly one"),
            "tag mismatch": (release_json(tag_name="v2026.1.1.1"), "holds a bundle for"),
            "too big": (release_json(assets=[
                {**release_json()["assets"][0], "size": store.MAX_BUNDLE_BYTES + 1},
                release_json()["assets"][1]]), "larger than allowed"),
            "not json": (None, "isn't valid JSON"),
        }
        for label, (release, message) in cases.items():
            with self.subTest(case=label):
                github = FakeGitHub(release=release)
                if release is None:
                    github.release = {}
                    github.__class__ = type("Broken", (FakeGitHub,), {
                        "__call__": lambda self, r, t: FakeResponse(b"<html>", r.full_url),
                    })
                with self.assertRaisesRegex(PackInstallError, message):
                    self.run_update(github)

    def test_downloads_only_over_https_from_github(self) -> None:
        bad_urls = [
            "http://github.com/x/y.tar.gz",
            "https://evil.example/mantha-packs.tar.gz",
            "https://github.com.evil.example/x",
        ]
        for url in bad_urls:
            with self.subTest(url=url):
                release = release_json()
                release["assets"][0]["browser_download_url"] = url
                with self.assertRaisesRegex(PackInstallError, "refusing to download"):
                    self.run_update(FakeGitHub(release=release))
        # A redirect off GitHub is refused too.
        github = FakeGitHub(redirect={DOWNLOAD + TARBALL + ".minisig": "https://evil.example/sig"})
        with self.assertRaisesRegex(PackInstallError, "refusing to download"):
            self.run_update(github)

    def test_network_errors_are_friendly(self) -> None:
        def offline(request, timeout):
            raise urllib.error.URLError("Name or service not known")

        with self.assertRaisesRegex(PackInstallError, "couldn't reach GitHub"):
            update.check(home=self.home, opener=offline)

    def test_repo_override_is_validated(self) -> None:
        with patch.dict(os.environ, {"MANTHA_RAY_PACKS_REPO": "someone/fork"}):
            self.assertEqual(update.release_repo(), "someone/fork")
        with patch.dict(os.environ, {"MANTHA_RAY_PACKS_REPO": "../../evil"}):
            with self.assertRaises(PackInstallError):
                update.release_repo()


class ApiTests(unittest.TestCase):
    def test_update_endpoint(self) -> None:
        try:
            from fastapi.testclient import TestClient

            from static_triage.web_api import create_app
            from static_triage.web_service import ScanService
        except (ImportError, RuntimeError):
            self.skipTest("fastapi and httpx are required for API tests")

        class Controller:
            image = "static-triage:core"
            engine = "docker"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "static").mkdir()
            (root / "static" / "index.html").write_text("<!doctype html>")
            app = create_app(ScanService(Controller()), "t", root / "static", "http://127.0.0.1:8765")
            client = TestClient(app, base_url="http://127.0.0.1")
            client.post("/api/session", headers={"X-Mantha-Ray-Token": "t"})
            status = update.UpdateCheck("2026.10.30.1", "2026.10.30.1", True, False, False, None)
            with patch.dict(os.environ, {"MANTHA_RAY_PACKS_HOME": str(root / "home")}), \
                    patch.object(update, "update", return_value=(status, None)):
                body = client.post("/api/packs/update").json()
            self.assertEqual(body["message"], "Rule packs are up to date (2026.10.30.1).")
            self.assertFalse(body["updated"])
            with patch.object(update, "update", side_effect=PackInstallError("couldn't reach GitHub: offline")):
                response = client.post("/api/packs/update")
            self.assertEqual(response.status_code, 400)
            self.assertIn("couldn't reach GitHub", response.json()["detail"])
            fresh = TestClient(app, base_url="http://127.0.0.1")
            self.assertEqual(fresh.post("/api/packs/update").status_code, 401)


if __name__ == "__main__":
    unittest.main()
