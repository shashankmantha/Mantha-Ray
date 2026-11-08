from __future__ import annotations

import unittest
from unittest.mock import patch

from static_triage.capa import CapaBatchResult, CapaBatchStatus, CapaResult, CapaStatus
from static_triage.clamav import ClamAVFinding, ClamAVLimitHit, ClamAVResult, ClamAVStatus
from static_triage.coverage import build_coverage, headline
from static_triage.floss import FlossBatchResult, FlossBatchStatus, FlossResult, FlossStatus
from static_triage.models import EntryKind, EntryState, InventoryEntry, RoutingClass, ToolInfo
from static_triage.reporting import _render_coverage
from static_triage.yara_scan import YARA_MAX_FILE_BYTES, YaraBatchResult, YaraFileResult, YaraMatch

TOOLS = [ToolInfo(name, f"/usr/bin/{name}", True) for name in ("clamscan", "yr", "capa", "floss")]


def entry(path: str, routing: RoutingClass = RoutingClass.OTHER, size: int = 100,
          state: EntryState = EntryState.INVENTORIED, kind: EntryKind = EntryKind.REGULAR_FILE,
          error: str | None = None) -> InventoryEntry:
    return InventoryEntry(path, kind, state, size_bytes=size, routing_class=routing, error=error)


def clamav(findings=(), limits=(), status=ClamAVStatus.CLEAN, run_complete=True, stopped=False):
    return ClamAVResult(
        status=status, complete=run_complete and not limits, return_code=0,
        findings=tuple(ClamAVFinding(path, "Win.Test-1") for path in findings),
        timed_out=status is ClamAVStatus.TIMED_OUT, output_truncated=False, duration_seconds=1.0,
        stdout="", stderr="", limits_exceeded=tuple(ClamAVLimitHit(p, limit) for p, limit in limits),
        run_complete=run_complete, stopped_by_user=stopped,
    )


def yara_file(path, reused=(), matched=False, complete=True, timed_out=False):
    matches = (YaraMatch("core-threats", "pack", "ns", "Rule", "threat", None, ()),) if matched else ()
    return YaraFileResult(path, tuple(reused), matches, complete, timed_out, False, None, 0.1)


def yara(results, status="completed"):
    return YaraBatchResult(status=status, complete=True, results=list(results))


def capa_file(path, reused=(), complete=True, timed_out=False, **extra):
    return CapaResult(
        status=CapaStatus.COMPLETED if complete else CapaStatus.TIMED_OUT, complete=complete,
        relative_path=path, return_code=0, capabilities=(), timed_out=timed_out,
        output_truncated=False, duration_seconds=1.0, stdout="", stderr="",
        reused_for=tuple(reused), **extra,
    )


def capa(results, limit=0, timeout=0):
    return CapaBatchResult(
        status=CapaBatchStatus.COMPLETED, complete=True, eligible_files=len(results),
        attempted_files=len(results), skipped_due_to_limit=limit,
        skipped_due_to_timeout=timeout, results=tuple(results), duration_seconds=1.0,
    )


def floss_file(path, mode="emulation", fully_scanned=None, reused=()):
    return FlossResult(
        status=FlossStatus.COMPLETED, complete=True, relative_path=path, return_code=0,
        strings=(), total_strings=0, strings_truncated=False, timed_out=False,
        output_truncated=False, duration_seconds=1.0, stdout="", stderr="",
        mode=mode, fully_scanned=fully_scanned, reused_for=tuple(reused),
    )


def floss(results, timeout=0):
    return FlossBatchResult(
        status=FlossBatchStatus.COMPLETED, complete=True, eligible_files=len(results),
        attempted_files=len(results), skipped_due_to_limit=0, skipped_due_to_timeout=timeout,
        results=tuple(results), duration_seconds=1.0,
    )


def gaps_by_path(coverage):
    found: dict[str, set[tuple[str, str]]] = {}
    for gap in coverage["gaps"]:
        found.setdefault(gap["relative_path"], set()).add((gap["analyzer"], gap["status"]))
    return found


class CoverageTests(unittest.TestCase):
    def test_everything_checked(self) -> None:
        entries = [
            entry("game.exe", RoutingClass.PE_EXECUTABLE),
            entry("copy/game.exe", RoutingClass.PE_EXECUTABLE),
            entry("data/level.pak"),
            entry("data", kind=EntryKind.DIRECTORY, size=0),
        ]
        coverage = build_coverage(
            entries, tools=TOOLS, clamav_result=clamav(findings=["data/level.pak"]),
            yara_result=yara([yara_file("game.exe", ["copy/game.exe"]), yara_file("data/level.pak")]),
            capa_result=capa([capa_file("game.exe", ["copy/game.exe"])]),
            floss_result=floss([floss_file("game.exe", reused=["copy/game.exe"])]),
        )
        self.assertEqual((coverage["files"], coverage["fully_checked"], coverage["with_gaps"]), (3, 3, 0))
        self.assertEqual(coverage["gaps"], [])
        self.assertEqual(coverage["analyzers"]["clamav"], {"applicable": 3, "done": 2, "finding": 1})
        self.assertEqual(coverage["analyzers"]["capa"], {"applicable": 2, "done": 2})
        self.assertEqual(headline(coverage), "Fully checked: 3 of 3 files")

    def test_every_kind_of_gap(self) -> None:
        entries = [
            entry("a.exe", RoutingClass.PE_EXECUTABLE),
            entry("big.exe", RoutingClass.PE_EXECUTABLE, size=40 * 1024**2),
            entry("late.dll", RoutingClass.PE_DLL),
            entry("huge.pak", size=YARA_MAX_FILE_BYTES + 1),
            entry("slow.zip"),
            entry("unreadable.bin", state=EntryState.ERROR, error="permission denied"),
            entry("link", kind=EntryKind.SYMLINK, size=0),
        ]
        coverage = build_coverage(
            entries, tools=TOOLS,
            clamav_result=clamav(limits=[("huge.pak", "MaxFileSize"), ("slow.zip", "MaxScanTime")]),
            yara_result=yara([
                yara_file("a.exe", matched=True), yara_file("big.exe"),
                yara_file("slow.zip", complete=False, timed_out=True),
            ]),
            capa_result=capa([capa_file("a.exe"), capa_file("big.exe", complete=False, timed_out=True,
                                                            stopped_at_budget_end=True)], timeout=1),
            floss_result=floss([floss_file("a.exe"), floss_file("big.exe", "plain", True)], timeout=1),
        )
        self.assertEqual(gaps_by_path(coverage), {
            "big.exe": {("capa", "timed_out"), ("floss", "partial")},
            "late.dll": {("yara", "not_reached"), ("capa", "not_reached"), ("floss", "not_reached")},
            "huge.pak": {("clamav", "too_large"), ("yara", "too_large")},
            "slow.zip": {("clamav", "timed_out"), ("yara", "timed_out")},
            "unreadable.bin": {("inventory", "failed")},
        })
        self.assertEqual(
            (coverage["files"], coverage["fully_checked"], coverage["partially_checked"],
             coverage["with_gaps"]),
            (6, 1, 0, 5),
        )
        self.assertIn("1 symlink or special file was listed", coverage["notes"][0])
        late = [g for g in coverage["gaps"] if g["relative_path"] == "late.dll" and g["analyzer"] == "capa"]
        self.assertEqual(late[0]["reason"], "capa's time budget ran out before it")
        # Partial gaps sort after real ones.
        self.assertEqual(coverage["gaps"][-1]["status"], "partial")

    def test_partial_only(self) -> None:
        entries = [entry("big.exe", RoutingClass.PE_EXECUTABLE, size=40 * 1024**2)]
        coverage = build_coverage(
            entries, tools=TOOLS, clamav_result=clamav(),
            yara_result=yara([yara_file("big.exe")]), capa_result=capa([capa_file("big.exe")]),
            floss_result=floss([floss_file("big.exe", "plain", False)]),
        )
        self.assertEqual((coverage["fully_checked"], coverage["partially_checked"]), (0, 1))
        self.assertEqual(headline(coverage), "Fully checked: 0 of 1 file (1 partly checked)")
        self.assertIn("only part of the file", coverage["gaps"][0]["reason"])

    def test_missing_stages(self) -> None:
        entries = [entry("a.exe", RoutingClass.PE_EXECUTABLE)]
        tools = [ToolInfo("clamscan", None, False), *TOOLS[1:]]
        coverage = build_coverage(
            entries, tools=tools, clamav_result=None,
            yara_result=YaraBatchResult(status="unavailable", complete=False,
                                        error="no rule packs are installed"),
            capa_result=None, floss_result=None,
        )
        reasons = {(g["analyzer"], g["status"], g["reason"]) for g in coverage["gaps"]}
        self.assertEqual(reasons, {
            ("clamav", "not_run", "ClamAV was unavailable"),
            ("capa", "not_run", "capa did not run"),
            ("floss", "not_run", "FLOSS did not run"),
        })
        self.assertEqual(coverage["analyzers"]["yara"], {"applicable": 0})
        self.assertTrue(any("YARA-X had no rule packs" in note for note in coverage["notes"]))
        stopped = build_coverage(
            entries, tools=TOOLS, clamav_result=clamav(status=ClamAVStatus.ERROR, run_complete=False,
                                                       stopped=True),
            yara_result=None, capa_result=None, floss_result=None, stopped=True,
        )
        self.assertEqual({g["status"] for g in stopped["gaps"]}, {"stopped"})

    def test_clamav_timeout_marks_unreported_files(self) -> None:
        entries = [entry("a.bin"), entry("b.bin")]
        coverage = build_coverage(
            entries, tools=TOOLS,
            clamav_result=clamav(findings=["a.bin"], status=ClamAVStatus.TIMED_OUT, run_complete=False),
            yara_result=yara([yara_file("a.bin"), yara_file("b.bin")]),
            capa_result=None, floss_result=None,
        )
        self.assertEqual(gaps_by_path(coverage), {"b.bin": {("clamav", "timed_out")}})

    def test_gap_list_is_capped(self) -> None:
        entries = [entry(f"f{i}.bin") for i in range(30)]
        with patch("static_triage.coverage.MAX_REPORTED_GAPS", 10):
            coverage = build_coverage(entries, tools=TOOLS, clamav_result=clamav(), yara_result=None,
                                      capa_result=None, floss_result=None)
        self.assertEqual((len(coverage["gaps"]), coverage["gap_count"], coverage["gaps_truncated"]),
                         (10, 30, True))

    def test_markdown_escapes_untrusted_reasons(self) -> None:
        entries = [entry("x.bin", state=EntryState.ERROR, error="[click](http://evil) *bold*")]
        coverage = build_coverage(entries, tools=TOOLS, clamav_result=clamav(), yara_result=None,
                                  capa_result=None, floss_result=None)
        text = "\n".join(_render_coverage(coverage, []))
        self.assertIn(r"\[click\](http://evil) *bold*", text)
        self.assertIn("Fully checked: 0 of 1 file (1 with gaps)", text)


if __name__ == "__main__":
    unittest.main()
