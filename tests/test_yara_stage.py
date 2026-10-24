from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from static_triage import stop_request
from static_triage.config import ScanLimits
from static_triage.container.command import (
    DockerScanRequest,
    HostScanError,
    build_docker_command,
    validate_request,
)
from static_triage.inventory import inventory_tree
from static_triage.models import OverallStatus
from static_triage.reporting import _determine_status, _render_yara
from static_triage.yara_scan import (
    YaraBatchResult,
    YaraFileResult,
    YaraMatch,
    externals_for,
    run_yara_stage,
    summary_message,
)

from test_packs import write_bundle

# A stand-in for `yr`: "compile" records the rule sources, "scan" reports a
# match for every "MATCH:<namespace>:<rule>" marker in the scanned file and
# echoes the filename external, so the orchestration can be tested anywhere.
FAKE_YR = r'''#!PYTHON
import json, sys, time
args = sys.argv[1:]
if args[0] == "--version":
    print("yara-x-cli fake"); sys.exit(0)
defines = {}
i = 0
rest = []
while i < len(args):
    if args[i] == "--define":
        name, value = args[i + 1].split("=", 1)
        defines[name] = json.loads(value)
        i += 2
    elif args[i] in ("--output", "--compiled-rules", "--output-format", "--timeout",
                     "--max-matches-per-pattern", "--threads"):
        rest.append((args[i], args[i + 1])); i += 2
    else:
        rest.append(args[i]); i += 1
if args[0] == "compile":
    output = dict(x for x in rest if isinstance(x, tuple))["--output"]
    sources = [x for x in rest[1:] if isinstance(x, str) and not x.startswith("--")]
    for source in sources:
        if "BROKEN" in open(source.split(":", 1)[1]).read():
            print("error: syntax error in " + source, file=sys.stderr); sys.exit(1)
    json.dump(sources, open(output, "w")); sys.exit(0)
target = [x for x in rest[1:] if isinstance(x, str) and not x.startswith("--")][-1]
data = open(target, "rb").read().decode("latin-1")
if "SLEEP" in data:
    time.sleep(int(dict(x for x in rest if isinstance(x, tuple))["--timeout"]))
    print("error: timeout", file=sys.stderr); sys.exit(1)
if "CRASH" in data:
    print("error: boom", file=sys.stderr); sys.exit(2)
rules = []
for part in data.split("MATCH:")[1:]:
    ns, rule = part.split(":")[:2]
    rule = rule.split()[0]
    rules.append({"identifier": rule, "namespace": ns,
                  "meta": [["description", "fake " + rule], ["filename", defines["filename"]]],
                  "tags": ["t"]})
print(json.dumps({"path": target, "rules": rules}))
'''


def fake_yr(directory: Path) -> str:
    path = directory / "yr"
    path.write_text(FAKE_YR.replace("#!PYTHON", "#!" + sys.executable))
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


def real_yr() -> str | None:
    return os.environ.get("MANTHA_RAY_YR") or shutil.which("yr")


def install(packs_root: Path, **kwargs) -> Path:
    write_bundle(packs_root / "bundle", **kwargs)
    (packs_root / "install.json").write_text(
        json.dumps({"bundle_version": kwargs.get("version", "2026.10.24.1"), "verified": True})
    )
    return packs_root


def sample(root: Path, files: dict[str, bytes]) -> list:
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    entries, _ = inventory_tree(root, ScanLimits())
    return entries


class StageTests(unittest.TestCase):
    def setUp(self) -> None:
        stop_request.reset()
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        self.yr = fake_yr(self.root)
        self.scan_root = self.root / "sample"
        self.scan_root.mkdir()

    def tearDown(self) -> None:
        stop_request.reset()
        self._temporary.cleanup()

    def run_stage(self, entries, packs_root, **kwargs) -> YaraBatchResult:
        self.messages: list[str] = []
        return run_yara_stage(
            entries, self.scan_root, executable=self.yr, app_version="0.1.0",
            packs_root=packs_root, on_message=self.messages.append, **kwargs,
        )

    def test_no_packs_is_unavailable_not_incomplete(self) -> None:
        entries = sample(self.scan_root, {"a.txt": b"x"})
        result = self.run_stage(entries, self.root / "nothing")
        self.assertEqual(result.status, "unavailable")
        self.assertIn("no YARA rule packs", result.error)

    def test_matches_get_bundle_severities_and_externals(self) -> None:
        packs = install(self.root / "packs")
        entries = sample(self.scan_root, {
            "game/cheat.exe": b"MZ MATCH:core-threats.tests:MAL_Test_Stealer ",
            "game/steam_api64.dll": b"MATCH:core-threats.tests:SUSP_Test_Name ",
            "game/readme.txt": b"nothing here",
            "other/unknown.bin": b"MATCH:core-threats.tests:Unlisted MATCH:nope.x:Foreign ",
        })
        result = self.run_stage(entries, packs, workers=2)
        self.assertEqual(result.status, "completed")
        self.assertTrue(result.complete)
        by_path = {r.relative_path: r for r in result.results}
        cheat = by_path["game/cheat.exe"].matches[0]
        self.assertEqual(
            (cheat.pack, cheat.kind, cheat.namespace, cheat.rule, cheat.severity),
            ("core-threats", "detection", "tests", "MAL_Test_Stealer", "threat"),
        )
        self.assertEqual(cheat.description, "fake MAL_Test_Stealer")
        self.assertEqual(by_path["game/steam_api64.dll"].matches[0].severity, "suspicious")
        # Rules missing from severities.json are info; unknown namespaces are ignored.
        self.assertEqual([m.severity for m in by_path["other/unknown.bin"].matches], ["info"])
        self.assertEqual(result.severity_counts(), {"threat": 1, "suspicious": 1, "info": 1})
        self.assertTrue(any(m.startswith("YARA-X match (threat): game/cheat.exe") for m in self.messages))
        report = result.to_dict()
        self.assertEqual(report["matched_files"], 3)
        self.assertEqual([r["relative_path"] for r in report["results"]][0], "game/cheat.exe")
        self.assertNotIn("game/readme.txt", [r["relative_path"] for r in report["results"]])
        self.assertEqual(report["bundle"]["version"], "2026.10.24.1")
        self.assertTrue(report["bundle"]["verified"])

    def test_identical_files_scanned_once_without_externals(self) -> None:
        packs = install(self.root / "packs", externals=[])
        data = b"MATCH:core-threats.tests:MAL_Test_Stealer "
        entries = sample(self.scan_root, {"v1/a.dll": data, "v2/a.dll": data, "v3/b.dll": data})
        result = self.run_stage(entries, packs)
        self.assertEqual((result.unique_files, result.duplicate_scans_avoided), (1, 2))
        self.assertEqual(result.results[0].reused_for, ("v2/a.dll", "v3/b.dll"))
        self.assertEqual(result.severity_counts()["threat"], 3)

    def test_identical_files_scanned_separately_with_externals(self) -> None:
        packs = install(self.root / "packs")
        data = b"MATCH:core-threats.tests:MAL_Test_Stealer "
        entries = sample(self.scan_root, {"v1/a.dll": data, "v2/a.dll": data})
        result = self.run_stage(entries, packs)
        self.assertEqual((result.unique_files, result.duplicate_scans_avoided), (2, 0))

    def test_broken_bundle_is_an_error(self) -> None:
        packs = install(self.root / "packs")
        (packs / "bundle" / "manifest.json").write_text("{}")
        result = self.run_stage(sample(self.scan_root, {"a": b"x"}), packs)
        self.assertEqual(result.status, "error")
        self.assertIn("invalid", result.error)

    def test_record_must_match_bundle(self) -> None:
        packs = install(self.root / "packs")
        (packs / "install.json").write_text(json.dumps({"bundle_version": "2026.1.1.1", "verified": True}))
        result = self.run_stage(sample(self.scan_root, {"a": b"x"}), packs)
        self.assertEqual(result.status, "error")

    def test_pack_that_does_not_compile_is_an_error(self) -> None:
        packs = install(self.root / "packs", rules="rule BROKEN_Rule { condition: true }\n",
                        severities={})
        result = self.run_stage(sample(self.scan_root, {"a": b"x"}), packs)
        self.assertEqual(result.status, "error")
        self.assertIn("compile", result.error)

    def test_other_edition_only_is_unavailable(self) -> None:
        packs = install(self.root / "packs", editions=["lite"])
        result = self.run_stage(sample(self.scan_root, {"a": b"x"}), packs)
        self.assertEqual(result.status, "unavailable")

    def test_failures_make_it_incomplete(self) -> None:
        packs = install(self.root / "packs")
        entries = sample(self.scan_root, {"bad.bin": b"CRASH", "ok.bin": b"fine"})
        result = self.run_stage(entries, packs)
        self.assertEqual(result.status, "incomplete")
        self.assertEqual(result.failed_files, 1)
        self.assertIn("1 scan failed", result.error)

    def test_timeout_and_budget(self) -> None:
        packs = install(self.root / "packs")
        entries = sample(self.scan_root, {"a_slow.bin": b"SLEEP", "b.bin": b"x", "c.bin": b"x"})
        result = self.run_stage(entries, packs, file_timeout_seconds=1, total_timeout_seconds=2.5)
        self.assertEqual(result.status, "incomplete")
        slow = next(r for r in result.results if r.relative_path == "a_slow.bin")
        self.assertTrue(slow.timed_out)
        self.assertGreaterEqual(result.skipped_due_to_timeout + result.scanned_files, 3)

    def test_stop_request(self) -> None:
        packs = install(self.root / "packs")
        entries = sample(self.scan_root, {"a.bin": b"x", "b.bin": b"x"})
        stop_request.request()
        result = self.run_stage(entries, packs)
        self.assertEqual(result.status, "error")  # compile is stopped too
        self.assertIn("stopped", result.error)

    def test_externals_for(self) -> None:
        self.assertEqual(
            externals_for("Game/Bin/Steam_API64.DLL"),
            {"filename": "Steam_API64.DLL", "filepath": "Game/Bin", "extension": ".dll"},
        )
        self.assertEqual(externals_for("a"), {"filename": "a", "filepath": "", "extension": ""})


def batch(severity: str | None, status: str = "completed") -> YaraBatchResult:
    result = YaraBatchResult(status=status, complete=status in ("completed", "unavailable"))
    if severity:
        match = YaraMatch("core-threats", "detection", "tests", "R", severity, None, ())
        result.results.append(YaraFileResult("a.exe", (), (match,), True, False, False, None, 0.1))
    return result


class VerdictTests(unittest.TestCase):
    def setUp(self) -> None:
        from types import SimpleNamespace

        from static_triage.clamav import ClamAVStatus
        clean = SimpleNamespace(status=ClamAVStatus.CLEAN, complete=True)
        risk = SimpleNamespace(high_concern=False, review_required=False)
        self.args = (
            clean,
            SimpleNamespace(complete=True, risk=risk),
            SimpleNamespace(complete=True, results=[]),
            SimpleNamespace(review_flags=0, errors=0, limit_exceeded=0),
        )

    def test_verdicts(self) -> None:
        cases = {
            None: OverallStatus.NO_INDICATORS_DETECTED,
            "info": OverallStatus.NO_INDICATORS_DETECTED,
            "suspicious": OverallStatus.NEEDS_REVIEW,
            "threat": OverallStatus.HIGH_CONCERN,
        }
        for severity, expected in cases.items():
            with self.subTest(severity=severity):
                self.assertEqual(_determine_status(*self.args, batch(severity)), expected)

    def test_threat_wins_over_incomplete_and_no_packs_is_not_a_gap(self) -> None:
        self.assertEqual(
            _determine_status(*self.args, batch("threat", "incomplete")),
            OverallStatus.HIGH_CONCERN,
        )
        self.assertEqual(
            _determine_status(*self.args, batch(None, "incomplete")),
            OverallStatus.INCOMPLETE,
        )
        self.assertEqual(
            _determine_status(*self.args, batch(None, "unavailable")),
            OverallStatus.NO_INDICATORS_DETECTED,
        )

    def test_markdown(self) -> None:
        result = batch("threat")
        result.bundle = {"version": "2026.10.24.1", "verified": False}
        text = "\n".join(_render_yara(result.to_dict()))
        self.assertIn("## YARA-X rule matches", text)
        self.assertIn("**unsigned**", text)
        self.assertIn("**threat**", text)
        self.assertIn("core-threats/R", text)
        self.assertIn("1 threat", summary_message(result))


class MountTests(unittest.TestCase):
    def test_packs_mounted_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("src", "results", "packs"):
                (root / name).mkdir()
            request = validate_request(DockerScanRequest(
                source_directory=root / "src", results_directory=root / "results",
                packs_directory=root / "packs",
            ))
            command = build_docker_command(request, "/usr/bin/docker", "name")
            self.assertIn(f"type=bind,source={root / 'packs'},target=/packs,readonly", command)
            without = build_docker_command(
                validate_request(DockerScanRequest(
                    source_directory=root / "src", results_directory=root / "results",
                )),
                "/usr/bin/docker", "name",
            )
            self.assertFalse(any("/packs" in part for part in without))
            with self.assertRaises(HostScanError):
                validate_request(DockerScanRequest(
                    source_directory=root / "src", results_directory=root / "results",
                    packs_directory=root / "src",
                ))


@unittest.skipUnless(real_yr(), "YARA-X (yr) is not installed; set MANTHA_RAY_YR to run")
class RealYaraTests(unittest.TestCase):
    def test_real_rules_and_filename_external(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packs = install(root / "packs")
            scan_root = root / "sample"
            scan_root.mkdir()
            entries = sample(scan_root, {
                "cheat.exe": b"MZ\x00\x00loginusers.vdf",
                "steam_api64.dll": b"anything",
                "notes.txt": b"loginusers.vdf but not a PE",
                'odd "name"\\.dll': b"x",
            })
            result = run_yara_stage(
                entries, scan_root, executable=real_yr(), app_version="0.1.0", packs_root=packs,
            )
        self.assertEqual(result.status, "completed", result.error)
        found = {(r.relative_path, m.rule, m.severity) for r in result.results for m in r.matches}
        self.assertEqual(found, {
            ("cheat.exe", "MAL_Test_Stealer", "threat"),
            ("steam_api64.dll", "SUSP_Test_Name", "suspicious"),
        })


if __name__ == "__main__":
    unittest.main()
