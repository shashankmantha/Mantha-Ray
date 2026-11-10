from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from static_triage.capa import CapaBatchResult, CapaBatchStatus, CapaCapability, CapaResult, CapaStatus
from static_triage.capa_risk import capability_groups, find_combinations
from static_triage.case_summary import capa_combination_lines
from static_triage.clamav import ClamAVStatus
from static_triage.models import OverallStatus
from static_triage.reporting import _determine_status

# (name, namespace, ATT&CK) as capa reports them.
GAME = [
    ("check for debugger via API", "anti-analysis/anti-debugging/debugger-detection", ["T1622"]),
    ("log keystrokes via raw input data", "collection/keylog", ["T1056.001"]),
    ("log keystrokes via polling", "collection/keylog", ["T1056.001"]),
    ("capture screenshot", "collection/screenshot", ["T1113"]),
    ("read clipboard data", "host-interaction/clipboard", ["T1115"]),
    ("allocate or change RWX memory", "host-interaction/process/inject", []),
    ("reference processor manufacturer constants", "anti-analysis/anti-vm/vm-detection", ["T1497.001"]),
    ("reference anti-VM strings targeting VMWare", "anti-analysis/anti-vm/vm-detection", ["T1497.001"]),
    ("send HTTP request", "communication/http/client", []),
    ("download and write a file", "communication/c2/file-transfer", ["T1105"]),
    ("encrypt data using AES", "data-manipulation/encryption/aes", ["T1027"]),
    ("create process on Windows", "host-interaction/process/create", []),
    ("link many functions at runtime", "linking/runtime-linking", ["T1129"]),
]
STEALER = [
    ("gather chrome based browser login information", "collection/browser", ["T1555.003"]),
    ("send HTTP request", "communication/http/client", []),
]
KEYLOGGER = [
    ("log keystrokes via application hook", "collection/keylog", ["T1056.001"]),
    ("send data on socket", "communication/socket/send", []),
]
INJECTOR = [
    ("inject dll", "host-interaction/process/inject", ["T1055.001"]),
    ("persist via Run registry key", "persistence/registry/run", ["T1547.001"]),
]
MINER = [
    ("reference cryptocurrency strings", "impact/cryptocurrency", ["T1496"]),
    ("schedule task via schtasks", "persistence/scheduled-tasks", ["T1053.005"]),
]
RANSOM = [("delete volume shadow copies", "impact/inhibit-system-recovery", ["T1490", "T1070.004"])]


def ids(found) -> list[str]:
    return [combo.identifier for combo in found]


def capa_result(path: str, capabilities) -> CapaResult:
    return CapaResult(
        status=CapaStatus.COMPLETED, complete=True, relative_path=path, return_code=0,
        capabilities=tuple(CapaCapability(n, ns, 1, tuple(a), ()) for n, ns, a in capabilities),
        timed_out=False, output_truncated=False, duration_seconds=1.0, stdout="", stderr="",
    )


def batch(*results: CapaResult, complete: bool = True) -> CapaBatchResult:
    return CapaBatchResult(
        status=CapaBatchStatus.COMPLETED if complete else CapaBatchStatus.PARTIAL,
        complete=complete, eligible_files=len(results), attempted_files=len(results),
        skipped_due_to_limit=0, skipped_due_to_timeout=0, results=tuple(results),
        duration_seconds=1.0,
    )


class CombinationTests(unittest.TestCase):
    def test_a_game_is_not_suspicious(self) -> None:
        self.assertEqual(find_combinations(GAME), ())

    def test_malware_patterns(self) -> None:
        self.assertEqual(ids(find_combinations(STEALER)), ["credential-theft-and-network"])
        self.assertEqual(ids(find_combinations(KEYLOGGER)), ["spying-and-network"])
        self.assertEqual(ids(find_combinations(INJECTOR)), ["injection-with-payload"])
        self.assertEqual(ids(find_combinations(MINER)), ["mining-with-stealth"])
        self.assertEqual(ids(find_combinations(RANSOM)), ["strong-indicator"])
        combo = find_combinations(STEALER)[0]
        self.assertEqual(combo.capabilities,
                         ("gather chrome based browser login information", "send HTTP request"))

    def test_a_game_with_one_bad_addition(self) -> None:
        self.assertEqual(ids(find_combinations(GAME + [KEYLOGGER[0]])), ["spying-and-network"])
        # A JIT's RWX memory plus a Run key is not "injection with persistence".
        self.assertEqual(find_combinations([GAME[5], INJECTOR[1]]), ())

    def test_door_kickers_2_false_alarms(self) -> None:
        # What policy 2 flagged in two Door Kickers 2 files (2026-11-10).
        openal = [
            ("hijack thread execution", "host-interaction/process/inject", ["T1055.003"]),
            ("capture microphone audio", "collection/microphone", ["T1123"]),
        ]
        game_exe = [
            ("schedule task via at", "persistence/scheduled-tasks", ["T1053.002"]),
            ("reference anti-VM strings", "anti-analysis/anti-vm/vm-detection", ["T1497.001"]),
            ("reference anti-VM strings targeting Parallels", "anti-analysis/anti-vm/vm-detection",
             ["T1497.001"]),
        ]
        self.assertEqual(find_combinations(openal), ())
        self.assertEqual(find_combinations(game_exe), ())
        # Real versions of the same ideas still count.
        self.assertEqual(ids(find_combinations([
            ("inject dll", "host-interaction/process/inject", ["T1055.001"]),
            ("capture webcam image", "collection/webcam", ["T1125"]),
        ])), ["injection-with-payload"])
        self.assertEqual(ids(find_combinations([
            ("schedule task via schtasks", "persistence/scheduled-tasks", ["T1053.005"]),
            ("patch Antimalware Scan Interface function", "anti-analysis/anti-av", ["T1562.001"]),
        ])), ["strong-indicator", "persistence-with-payload"])

    def test_routine_rules_have_no_groups(self) -> None:
        for name, namespace, attack in GAME[1:7]:
            with self.subTest(name=name):
                self.assertEqual(capability_groups(name, namespace, attack), frozenset())
        self.assertEqual(capability_groups(*KEYLOGGER[0]), frozenset({"spying"}))
        # File transfer isn't counted as plain networking as well.
        self.assertEqual(capability_groups(*GAME[9]), frozenset({"file-transfer"}))


class CaseRiskTests(unittest.TestCase):
    def test_score_is_the_worst_file_not_a_sum(self) -> None:
        many = batch(*(capa_result(f"lib{i}.dll", GAME) for i in range(30)))
        one = capa_result("lib0.dll", GAME).risk
        self.assertEqual(many.risk.score, one.score)
        self.assertFalse(many.risk.suspicious)

    def test_combinations_name_their_file(self) -> None:
        risk = batch(capa_result("game.exe", GAME), capa_result("bin/helper.dll", STEALER)).risk
        self.assertTrue(risk.suspicious)
        combos = risk.to_dict()["combinations"]
        self.assertEqual([(c["relative_path"], c["id"]) for c in combos],
                         [("bin/helper.dll", "credential-theft-and-network")])
        self.assertTrue(risk.to_dict()["high_concern"])  # older readers see it too


class VerdictTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clean = SimpleNamespace(status=ClamAVStatus.CLEAN, complete=True)
        self.floss = SimpleNamespace(complete=True, results=[])
        self.summary = SimpleNamespace(review_flags=0, errors=0, limit_exceeded=0)

    def verdict(self, capa, clamav=None, yara=None, floss=None):
        return _determine_status(clamav or self.clean, capa, floss or self.floss, self.summary, yara)

    def test_suspicious_capabilities(self) -> None:
        self.assertEqual(self.verdict(batch(capa_result("x.exe", STEALER))),
                         OverallStatus.SUSPICIOUS_CAPABILITIES)
        # Positive evidence counts even if other stages didn't finish.
        unfinished = batch(capa_result("x.exe", STEALER), complete=False)
        self.assertEqual(self.verdict(unfinished, floss=SimpleNamespace(complete=False, results=[])),
                         OverallStatus.SUSPICIOUS_CAPABILITIES)

    def test_detections_still_win(self) -> None:
        infected = SimpleNamespace(status=ClamAVStatus.INFECTED, complete=True)
        self.assertEqual(self.verdict(batch(capa_result("x.exe", STEALER)), clamav=infected),
                         OverallStatus.KNOWN_DETECTION)

    def test_a_clean_game_is_no_longer_high_concern(self) -> None:
        verdict = self.verdict(batch(*(capa_result(f"f{i}.dll", GAME) for i in range(47))))
        self.assertEqual(verdict, OverallStatus.NEEDS_REVIEW)


class SummaryTests(unittest.TestCase):
    def test_lines_from_a_saved_report(self) -> None:
        data = json.loads(json.dumps(batch(capa_result("game.exe", GAME),
                                           capa_result("bin/hook.dll", KEYLOGGER)).to_dict()))
        data["results"][1]["reused_for"] = ["v1/bin/hook.dll"]
        text = "\n".join(capa_combination_lines(data))
        self.assertIn("capa combinations: 1 file (SUSPICIOUS CAPABILITIES", text)
        self.assertIn("bin/hook.dll  (+1 identical copies)", text)
        self.assertIn("log keystrokes via application hook, send data on socket", text)
        self.assertNotIn("game.exe", text)
        self.assertEqual(capa_combination_lines({"results": [data["results"][0]]}),
                         ["capa combinations: none (policy 3)"])


if __name__ == "__main__":
    unittest.main()
