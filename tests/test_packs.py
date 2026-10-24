from __future__ import annotations

import base64
import io
import json
import os
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path

from static_triage.packs import store
from static_triage.packs.contract import (
    ContractError,
    bundle_version_key,
    declared_rules,
    pack_digest,
    validate_bundle,
)
from static_triage.packs.signing import SignatureError, parse_trusted_comment, verify_file

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "hermit"
VERSION = "2026.10.24.1"

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    HAVE_CRYPTO = ed25519 is not None
except ImportError:
    HAVE_CRYPTO = False


def hermit_tarball(directory: Path) -> Path:
    tarball = directory / f"mantha-packs-{VERSION}.tar.gz"
    tarball.write_bytes(base64.b64decode((FIXTURES / f"{tarball.name}.b64").read_text()))
    shutil.copy(FIXTURES / f"{tarball.name}.minisig", directory / f"{tarball.name}.minisig")
    return tarball


def public_key() -> str:
    return (FIXTURES / "test-key.pub").read_text()


def unpack(tarball: Path, directory: Path) -> Path:
    destination = directory / "unpacked"
    with tarfile.open(tarball) as archive:
        archive.extractall(destination, filter="data")
    return destination


RULES = """
private rule IsPE { condition: uint16(0) == 0x5A4D }
rule MAL_Test_Stealer : stealer {
  meta: description = "test stealer"
  strings: $a = "loginusers.vdf"
  condition: IsPE and $a
}
// rule Commented_Out { condition: true }
rule SUSP_Test_Name { condition: filename == "steam_api64.dll" }
"""


def write_bundle(
    root: Path,
    *,
    version: str = VERSION,
    rules: str = RULES,
    severities: dict[str, str] | None = None,
    externals: list[str] | None = None,
    editions: list[str] | None = None,
    min_app_version: str = "0.0.0",
) -> Path:
    pack = root / "packs" / "core-threats"
    (pack / "rules").mkdir(parents=True)
    (pack / "rules" / "tests.yar").write_text(rules)
    names = [name for name, public in declared_rules(rules).items() if public]
    (pack / "pack.json").write_text(json.dumps({
        "format": 1, "id": "core-threats", "version": 1, "kind": "detection",
        "editions": editions or ["all"], "description": "test pack",
        "rules": [
            {"namespace": "tests", "name": n, "file": "rules/tests.yar",
             "source": "tests", "licence": "CC0-1.0"}
            for n in names
        ],
        "externals": externals if externals is not None else ["filename"],
    }))
    (pack / "severities.json").write_text(json.dumps({
        "format": 1,
        "severities": severities if severities is not None else {
            "tests:MAL_Test_Stealer": "threat", "tests:SUSP_Test_Name": "suspicious",
        },
        "demoted": {}, "probation": {},
    }))
    (root / "manifest.json").write_text(json.dumps({
        "format": 1, "bundle_version": version, "created_at": "2026-10-24T03:00:00Z",
        "min_app_version": min_app_version, "yara_x_version": "1.22.0",
        "packs": [{"id": "core-threats", "version": 1, "sha256": pack_digest(pack)}],
        "sources": [{"name": "tests", "url": None, "revision": None, "licence": "CC0-1.0"}],
        "changes": "test",
    }))
    return root


def rehash(root: Path) -> None:
    manifest = json.loads((root / "manifest.json").read_text())
    for pack in manifest["packs"]:
        pack["sha256"] = pack_digest(root / "packs" / pack["id"])
    (root / "manifest.json").write_text(json.dumps(manifest))


class ContractTests(unittest.TestCase):
    def test_hermit_bundle_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = validate_bundle(unpack(hermit_tarball(Path(temporary)), Path(temporary)))
        self.assertEqual(bundle.bundle_version, VERSION)
        self.assertEqual(
            [(p.id, p.kind) for p in bundle.packs],
            [("core-threats", "detection"), ("cracked-software", "detection"),
             ("games", "recognition"), ("riskware", "recognition")],
        )
        core = bundle.packs[0]
        self.assertTrue(core.loaded_here)
        self.assertEqual(
            core.severity("examples__game_threats_yar", "MAL_Example_XMRig_Miner_Config"),
            "threat",
        )
        self.assertEqual(core.severity("examples__game_threats_yar", "Unlisted"), "info")

    def test_comment_markers_inside_strings_and_regexes(self) -> None:
        # Real YARA Forge rules have strings like "Accept: */*" and "http://".
        # Treating those as comments hid most of a real bundle's rules.
        text = (
            'rule First { strings: $a = "Accept: text/html, */*" condition: $a }\n'
            'rule Second { strings: $u = "http://example.org/a" condition: $u }\n'
            'rule Third { strings: $r = /GET \\/[a-z]+\\/\\*/ condition: $r }\n'
            'rule Fourth { strings: $q = "say \\"/*\\" here" condition: $q }\n'
            '/* rule Commented { condition: true } */\n'
            '// rule AlsoCommented { condition: true }\n'
            'private rule Helper { condition: true }\n'
            'rule Last { strings: $s = "end */" condition: $s and Helper }\n'
        )
        self.assertEqual(
            declared_rules(text),
            {"First": True, "Second": True, "Third": True, "Fourth": True,
             "Helper": False, "Last": True},
        )

    def test_versions_compare_as_numbers(self) -> None:
        self.assertGreater(bundle_version_key("2026.10.22.12"), bundle_version_key("2026.10.22.2"))
        with self.assertRaises(ContractError):
            bundle_version_key("2026.10.22")

    def test_rejections(self) -> None:
        def edit_json(path: str, change) -> callable:
            def apply(root: Path) -> None:
                target = root / path
                payload = json.loads(target.read_text())
                change(payload)
                target.write_text(json.dumps(payload))
            return apply

        def add_file(root: Path) -> None:
            (root / "packs" / "core-threats" / "notes.txt").write_text("x")

        def symlink(root: Path) -> None:
            (root / "packs" / "core-threats" / "rules" / "link.yar").symlink_to("/etc/passwd")

        def tamper_rule(root: Path) -> None:
            path = root / "packs" / "core-threats" / "rules" / "tests.yar"
            path.write_text(path.read_text() + "\n")

        cases = {
            "unknown manifest field": (edit_json("manifest.json", lambda m: m.update(extra=1)), False),
            "format 2": (edit_json("manifest.json", lambda m: m.update(format=2)), False),
            "bad version": (edit_json("manifest.json", lambda m: m.update(bundle_version="1.2")), False),
            "local pack": (edit_json("manifest.json", lambda m: m["packs"][0].update(id="local:x")), False),
            "extra file": (add_file, True),
            "symlink": (symlink, False),
            "rule edited": (tamper_rule, False),
            "unknown severity": (
                edit_json("packs/core-threats/severities.json",
                          lambda s: s["severities"].update({"tests:MAL_Test_Stealer": "critical"})), True),
            "severity for unlisted rule": (
                edit_json("packs/core-threats/severities.json",
                          lambda s: s["severities"].update({"tests:Nope": "info"})), True),
            "probation not info": (
                edit_json("packs/core-threats/severities.json",
                          lambda s: s["probation"].update({"tests:MAL_Test_Stealer": "2026-11-01"})), True),
            "listed private rule": (
                edit_json("packs/core-threats/pack.json",
                          lambda p: p["rules"].append({**p["rules"][0], "name": "IsPE"})), True),
            "listed commented rule": (
                edit_json("packs/core-threats/pack.json",
                          lambda p: p["rules"].append({**p["rules"][0], "name": "Commented_Out"})), True),
            "bad external": (edit_json("packs/core-threats/pack.json", lambda p: p.update(externals=["env"])), True),
            "id mismatch": (edit_json("packs/core-threats/pack.json", lambda p: p.update(id="other")), True),
        }
        for label, (mutate, fix_hash) in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                root = write_bundle(Path(temporary) / "b")
                validate_bundle(root)
                mutate(root)
                if fix_hash:
                    try:
                        rehash(root)
                    except ContractError:
                        pass
                with self.assertRaises(ContractError):
                    validate_bundle(root)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography is not installed")
class SignatureTests(unittest.TestCase):
    def test_hermit_signature_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tarball = hermit_tarball(Path(temporary))
            comment = verify_file(tarball, Path(f"{tarball}.minisig"), public_key())
        version, sha = parse_trusted_comment(comment)
        self.assertEqual(version, VERSION)
        self.assertEqual(len(sha), 64)

    def test_tampering_and_wrong_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tarball = hermit_tarball(Path(temporary))
            signature = Path(f"{tarball}.minisig")
            data = bytearray(tarball.read_bytes())
            data[len(data) // 2] ^= 1
            tarball.write_bytes(bytes(data))
            with self.assertRaises(SignatureError):
                verify_file(tarball, signature, public_key())

            tarball = hermit_tarball(Path(temporary))
            lines = signature.read_text().splitlines()
            lines[2] = lines[2].replace(VERSION, "2026.10.24.9")
            signature.write_text("\n".join(lines) + "\n")
            with self.assertRaises(SignatureError):
                verify_file(tarball, signature, public_key())

            hermit_tarball(Path(temporary))
            other = "untrusted comment: x\nRWQBAgMEBQYHCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            with self.assertRaises(SignatureError):
                verify_file(tarball, signature, other)

    def test_comment_is_matched_whole(self) -> None:
        sha = "a" * 64
        self.assertEqual(parse_trusted_comment(f"mantha-packs {VERSION} sha256:{sha}"), (VERSION, sha))
        for bad in (
            f"mantha-packs {VERSION} sha256:{sha} extra",
            f"mantha-packs {VERSION}",
            f"mantha-packs {VERSION}  sha256:{sha}",
            f"other {VERSION} sha256:{sha}",
        ):
            with self.subTest(comment=bad), self.assertRaises(SignatureError):
                parse_trusted_comment(bad)


def ok_check(staging: Path) -> dict:
    validate_bundle(staging / "bundle")
    return {"ok": True}


@unittest.skipUnless(HAVE_CRYPTO, "cryptography is not installed")
class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        self.home = self.root / "home"

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def install(self, tarball: Path, **kwargs) -> store.Installed:
        kwargs.setdefault("compile_check", ok_check)
        return store.install_signed(
            tarball, public_key_text=public_key(), home=self.home, **kwargs,
        )

    def test_signed_install_then_reinstall_refused(self) -> None:
        installed = self.install(hermit_tarball(self.root))
        self.assertTrue(installed.verified)
        self.assertEqual(store.current_install_dir(self.home), self.home / "installs" / VERSION)
        record = json.loads((installed.directory / "install.json").read_text())
        self.assertEqual(record["bundle_version"], VERSION)
        self.assertTrue(record["verified"])
        with self.assertRaisesRegex(store.PackInstallError, "already installed"):
            self.install(hermit_tarball(self.root))

    def test_rollback_from_download_refused(self) -> None:
        state = {"current": None, "highest_signed": "2026.10.25.1", "history": []}
        self.home.mkdir(parents=True)
        (self.home / "state.json").write_text(json.dumps(state))
        with self.assertRaisesRegex(store.PackInstallError, "rollback refused"):
            self.install(hermit_tarball(self.root))
        self.assertIsNone(store.current_install_dir(self.home))

    def test_tampered_bundle_leaves_current_install(self) -> None:
        self.install(hermit_tarball(self.root))
        before = (self.home / "state.json").read_text()
        tarball = hermit_tarball(self.root)
        data = bytearray(tarball.read_bytes())
        data[100] ^= 1
        tarball.write_bytes(bytes(data))
        with self.assertRaisesRegex(store.PackInstallError, "signature"):
            self.install(tarball)
        self.assertEqual((self.home / "state.json").read_text(), before)
        self.assertEqual([p.name for p in (self.home / "installs").iterdir()], [VERSION])

    def test_failed_compile_check_changes_nothing(self) -> None:
        def failing(staging: Path) -> dict:
            raise store.PackInstallError("the rules don't compile: boom")

        with self.assertRaisesRegex(store.PackInstallError, "boom"):
            self.install(hermit_tarball(self.root), compile_check=failing)
        self.assertIsNone(store.current_install_dir(self.home))
        self.assertEqual(list((self.home / "installs").iterdir()), [])

    def test_unsigned_install_and_explicit_rollback(self) -> None:
        self.install(hermit_tarball(self.root))
        folder = write_bundle(self.root / "dev", version="2026.10.26.1")
        installed = store.install_unsigned(folder, compile_check=ok_check, home=self.home)
        self.assertFalse(installed.verified)
        self.assertEqual(installed.directory.name, "2026.10.26.1-unsigned")
        status = store.status(self.home)
        self.assertEqual(status["installed"]["version"], "2026.10.26.1")
        self.assertEqual(status["highest_signed"], VERSION)  # unsigned never raises the floor
        back = store.rollback(self.home)
        self.assertEqual((back.version, back.verified), (VERSION, True))
        with self.assertRaisesRegex(store.PackInstallError, "no earlier install"):
            store.rollback(self.home)

    def test_newer_app_version_required(self) -> None:
        folder = write_bundle(self.root / "dev", min_app_version="99.0.0")
        with self.assertRaisesRegex(store.PackInstallError, "needs Mantha Ray 99.0.0"):
            store.install_unsigned(folder, compile_check=ok_check, home=self.home)

    def test_unsafe_archives(self) -> None:
        def archive(add) -> Path:
            path = self.root / "evil.tar.gz"
            with tarfile.open(path, "w:gz") as tar:
                add(tar)
            return path

        def member(name: str, kind=tarfile.REGTYPE, target: str = "") -> tarfile.TarInfo:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.linkname = target
            return info

        cases = {
            "escape": lambda t: t.addfile(member("../evil"), io.BytesIO(b"")),
            "absolute": lambda t: t.addfile(member("/tmp/evil"), io.BytesIO(b"")),
            "symlink": lambda t: t.addfile(member("link", tarfile.SYMTYPE, "/etc/passwd")),
            "hardlink": lambda t: t.addfile(member("link", tarfile.LNKTYPE, "manifest.json")),
            "device": lambda t: t.addfile(member("dev", tarfile.CHRTYPE)),
        }
        for label, add in cases.items():
            with self.subTest(case=label):
                destination = self.root / f"out-{label}"
                with self.assertRaises(store.PackInstallError):
                    store.safe_extract(archive(add), destination)
                self.assertFalse(Path("/tmp/evil").exists() and label == "absolute")

    def test_missing_public_key_message(self) -> None:
        if store.PUBLIC_KEY_PATH.is_file():
            self.skipTest("a release key is configured")
        with self.assertRaisesRegex(store.PackInstallError, "no release public key"):
            store.install_signed(hermit_tarball(self.root), home=self.home)

    def test_packs_home_override(self) -> None:
        old = os.environ.get("MANTHA_RAY_PACKS_HOME")
        os.environ["MANTHA_RAY_PACKS_HOME"] = str(self.home)
        try:
            self.assertEqual(store.packs_home(), self.home)
        finally:
            if old is None:
                del os.environ["MANTHA_RAY_PACKS_HOME"]
            else:
                os.environ["MANTHA_RAY_PACKS_HOME"] = old


if __name__ == "__main__":
    unittest.main()