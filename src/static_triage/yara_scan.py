from __future__ import annotations

import json
import shutil
import tempfile
import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from . import stop_request
from .deduplication import AnalysisGroup, group_entries_by_sha256
from .file_progress import format_duration, short_path
from .models import EntryKind, EntryState, InventoryEntry
from .packs.contract import (
    EXTERNALS,
    BundleInfo,
    ContractError,
    PackInfo,
    app_version_key,
    validate_bundle,
    validate_pack,
)
from .runner import CommandResult, run_command

# Where the host mounts the installed bundle (read-only) and the small JSON
# record it keeps about that install: version and whether it was signed.
PACKS_MOUNT = Path("/packs")
# Your own rule files (local packs), mounted read-only beside the bundle.
LOCAL_PACKS_MOUNT = Path("/packs-local")

YARA_FILE_TIMEOUT_SECONDS = 60
YARA_TOTAL_TIMEOUT_SECONDS = 30 * 60
YARA_COMPILE_TIMEOUT_SECONDS = 300
# Files are memory-mapped by YARA-X, so this bounds time more than memory.
YARA_MAX_FILE_BYTES = 1024**3
MAX_MATCHES_PER_FILE = 100
MAX_MATCHES_PER_PATTERN = 1000
MAX_REPORTED_FILES = 2000
MAX_DESCRIPTION_CHARS = 300
PROGRESS_INTERVAL_SECONDS = 5.0

YR_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "LC_ALL": "C",
    "LANG": "C",
    "HOME": "/tmp/yr-home",
    "USER": "static-triage",
    "LOGNAME": "static-triage",
}

SEVERITY_ORDER = {"threat": 0, "suspicious": 1, "info": 2}

ProgressMessage = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class YaraMatch:
    pack: str
    kind: str
    namespace: str
    rule: str
    severity: str
    description: str | None
    tags: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack": self.pack,
            "kind": self.kind,
            "namespace": self.namespace,
            "rule": self.rule,
            "severity": self.severity,
            "description": self.description,
            "tags": list(self.tags),
        }


@dataclass(frozen=True, slots=True)
class YaraFileResult:
    relative_path: str
    reused_for: tuple[str, ...]
    matches: tuple[YaraMatch, ...]
    complete: bool
    timed_out: bool
    stopped_by_user: bool
    error: str | None
    duration_seconds: float
    matches_truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "reused_for": list(self.reused_for),
            "matches": [match.to_dict() for match in self.matches],
            "matches_truncated": self.matches_truncated,
            "complete": self.complete,
            "timed_out": self.timed_out,
            "stopped_by_user": self.stopped_by_user,
            "error": self.error,
            "duration_seconds": round(self.duration_seconds, 3),
        }


@dataclass(frozen=True, slots=True)
class LoadedRules:
    bundle: BundleInfo | None  # None when only local packs are installed
    compiled: Path
    packs: tuple[PackInfo, ...]  # the ones compiled into `compiled`
    # compiled namespace -> (pack, the namespace inside the pack)
    by_namespace: dict[str, tuple[PackInfo, str]]
    skipped: tuple[dict[str, str], ...]  # packs not loaded, with why
    uses_externals: bool


@dataclass(slots=True)
class YaraBatchResult:
    status: str
    complete: bool
    error: str | None = None
    bundle: dict[str, Any] | None = None
    packs: list[dict[str, Any]] = field(default_factory=list)
    rule_count: int = 0
    eligible_files: int = 0
    unique_files: int = 0
    scanned_files: int = 0
    duplicate_scans_avoided: int = 0
    skipped_due_to_size: int = 0
    skipped_due_to_timeout: int = 0
    failed_files: int = 0
    timed_out_files: int = 0
    stopped_files: int = 0
    results: list[YaraFileResult] = field(default_factory=list)
    duration_seconds: float | None = None
    workers: int = 1

    @property
    def matched_files(self) -> list[YaraFileResult]:
        return [r for r in self.results if r.matches]

    def severity_counts(self) -> dict[str, int]:
        counts = {"threat": 0, "suspicious": 0, "info": 0}
        for result in self.results:
            for match in result.matches:
                counts[match.severity] += 1 + len(result.reused_for)
        return counts

    def to_dict(self) -> dict[str, Any]:
        reported = sorted(
            (r for r in self.results if r.matches or not r.complete),
            key=lambda r: (
                min((SEVERITY_ORDER[m.severity] for m in r.matches), default=3),
                r.relative_path,
            ),
        )
        return {
            "status": self.status,
            "complete": self.complete,
            "error": self.error,
            "engine": "yara-x",
            "bundle": self.bundle,
            "packs": self.packs,
            "rule_count": self.rule_count,
            "eligible_files": self.eligible_files,
            "unique_files": self.unique_files,
            "scanned_files": self.scanned_files,
            "duplicate_scans_avoided": self.duplicate_scans_avoided,
            "skipped_due_to_size": self.skipped_due_to_size,
            "skipped_due_to_timeout": self.skipped_due_to_timeout,
            "failed_files": self.failed_files,
            "timed_out_files": self.timed_out_files,
            "stopped_files": self.stopped_files,
            "matched_files": len(self.matched_files),
            "severity_counts": self.severity_counts(),
            "limits": {
                "file_timeout_seconds": YARA_FILE_TIMEOUT_SECONDS,
                "total_timeout_seconds": YARA_TOTAL_TIMEOUT_SECONDS,
                "max_file_bytes": YARA_MAX_FILE_BYTES,
                "max_matches_per_file": MAX_MATCHES_PER_FILE,
            },
            # Only files with matches or problems; clean files are counted above.
            "results": [r.to_dict() for r in reported[:MAX_REPORTED_FILES]],
            "results_truncated": len(reported) > MAX_REPORTED_FILES,
            "duration_seconds": self.duration_seconds,
            "workers": self.workers,
        }


class RulesUnavailable(Exception):
    """No usable packs: the stage is reported as unavailable, not failed."""


class RulesError(Exception):
    """Packs are installed but can't be used: the stage is reported as an error."""


def read_install_record(packs_root: Path) -> dict[str, Any]:
    # Written by the host's pack installer next to the bundle data. Only the
    # two fields below are used, and both are checked against the bundle.
    path = packs_root / "install.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    version = payload.get("bundle_version")
    verified = payload.get("verified")
    return {
        "bundle_version": version if isinstance(version, str) else None,
        "verified": verified is True,
    }


def _bundle_dict(bundle: BundleInfo, verified: bool) -> dict[str, Any]:
    return {
        "version": bundle.bundle_version,
        "created_at": bundle.created_at,
        "verified": verified,
        "yara_x_version": bundle.yara_x_version,
        "changes": bundle.changes[:500],
    }


def _pack_dict(pack: PackInfo, loaded: bool, reason: str | None = None) -> dict[str, Any]:
    counts = {"threat": 0, "suspicious": 0, "info": 0}
    for key in pack.rules:
        counts[pack.severities.get(key, "info")] += 1
    return {
        "id": pack.id,
        "version": pack.version,
        "kind": pack.kind,
        "description": pack.description[:300],
        "rules": len(pack.rules),
        "local": pack.is_local,
        "severity_counts": counts,
        "without_severity": pack.without_severity,
        "loaded": loaded,
        "not_loaded_reason": reason,
    }


def compiled_namespace(pack: PackInfo, namespace: str) -> str:
    # yr reads "namespace:path", so the colon in "local:<name>" can't be used.
    # Bundle pack ids have no dots, so "local." can't collide with one.
    if pack.is_local:
        return f"local.{pack.id.split(':', 1)[1]}.{namespace}"
    return f"{pack.id}.{namespace}"


def _define_arguments(values: dict[str, str]) -> list[str]:
    # yr parses each value as JSON, so json.dumps escapes untrusted names.
    arguments: list[str] = []
    for name in EXTERNALS:
        arguments += ["--define", f"{name}={json.dumps(values.get(name, ''))}"]
    return arguments


def _compile(
    executable: str,
    sources: list[tuple[str, Path]],
    output: Path,
) -> CommandResult:
    command = [
        executable, "compile",
        "--output", str(output),
        "--disable-warnings",
        *_define_arguments({}),
        *(f"{namespace}:{path}" for namespace, path in sources),
    ]
    return run_command(
        command,
        timeout_seconds=YARA_COMPILE_TIMEOUT_SECONDS,
        max_output_bytes=200_000,
        env=YR_ENV,
        stoppable=True,
    )


def _first_error(result: CommandResult) -> str:
    text = (result.stderr or result.stdout or "").strip()
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:300]
    if result.timed_out:
        return "timed out"
    return f"exit code {result.return_code}"


def _load_bundle(
    packs_root: Path,
    app_version: str,
) -> tuple[BundleInfo | None, dict[str, Any]]:
    bundle_root = packs_root / "bundle"
    if not bundle_root.is_dir():
        return None, {}
    record = read_install_record(packs_root)
    try:
        bundle = validate_bundle(bundle_root)
    except (ContractError, OSError) as exc:
        raise RulesError(f"the installed rule packs are invalid: {exc}") from exc
    if record.get("bundle_version") not in (None, bundle.bundle_version):
        raise RulesError("the installed rule packs don't match their install record")
    try:
        too_new = app_version_key(bundle.min_app_version) > app_version_key(app_version)
    except ContractError:
        too_new = True
    if too_new:
        raise RulesError(
            f"the installed rule packs need Mantha Ray {bundle.min_app_version} or newer"
        )
    return bundle, record


def _load_local(
    local_root: Path | None,
    skipped: list[dict[str, str]],
) -> list[PackInfo]:
    if local_root is None or not local_root.is_dir():
        return []
    packs: list[PackInfo] = []
    for directory in sorted(local_root.iterdir()):
        if directory.name.startswith(".") or directory.is_symlink() or not directory.is_dir():
            continue
        try:
            packs.append(validate_pack(directory, local=True))
        except (ContractError, OSError) as exc:
            skipped.append({"id": f"local:{directory.name}", "reason": f"invalid: {exc}"})
    return packs


def compile_rules(
    packs_root: Path,
    work_dir: Path,
    *,
    executable: str,
    app_version: str,
    local_root: Path | None = None,
) -> tuple[LoadedRules, dict[str, Any]]:
    """Validate the mounted bundle and local packs, and compile them.

    Returns the compiled rules and the bundle's install record. Raises
    RulesUnavailable when nothing is installed, RulesError when what is
    installed can't be used.
    """

    skipped: list[dict[str, str]] = []
    local = _load_local(local_root, skipped)
    try:
        bundle, record = _load_bundle(packs_root, app_version)
    except RulesError as exc:
        if not local:
            raise
        # Your own rules still run; the bundle problem is reported.
        bundle, record = None, {}
        skipped.append({"id": "bundle", "reason": str(exc)})

    candidates: list[PackInfo] = []
    for pack in bundle.packs if bundle else ():
        if not pack.loaded_here:
            skipped.append({"id": pack.id, "reason": "not for this edition"})
        elif not pack.rule_files:
            skipped.append({"id": pack.id, "reason": "no rules"})
        else:
            candidates.append(pack)
    candidates += [pack for pack in local if pack.rule_files]
    if not candidates:
        if bundle is None and not local:
            raise RulesUnavailable("no YARA rule packs are installed")
        raise RulesUnavailable("the installed rule packs have no rules for this edition")

    output = work_dir / "rules.yarx"

    def sources(packs: list[PackInfo]) -> list[tuple[str, Path]]:
        return [
            (compiled_namespace(pack, namespace), path)
            for pack in packs
            for namespace, path in pack.rule_files
        ]

    result = _compile(executable, sources(candidates), output)
    if result.stopped:
        raise RulesError(stop_request.STOPPED_MESSAGE)
    if result.return_code != 0:
        # Find the packs that fail on their own and leave them out, so one
        # bad pack doesn't take the others down with it.
        good: list[PackInfo] = []
        for pack in candidates:
            alone = _compile(executable, sources([pack]), work_dir / "check.yarx")
            if alone.return_code == 0:
                good.append(pack)
            else:
                skipped.append({"id": pack.id, "reason": f"doesn't compile: {_first_error(alone)}"})
        (work_dir / "check.yarx").unlink(missing_ok=True)
        if not good:
            raise RulesError(f"no rule pack compiles: {_first_error(result)}")
        candidates = good
        result = _compile(executable, sources(candidates), output)
        if result.return_code != 0:
            raise RulesError(f"the rule packs don't compile together: {_first_error(result)}")

    loaded = LoadedRules(
        bundle=bundle,
        compiled=output,
        packs=tuple(candidates),
        by_namespace={
            compiled_namespace(pack, namespace): (pack, namespace)
            for pack in candidates
            for namespace, _ in pack.rule_files
        },
        skipped=tuple(skipped),
        uses_externals=any(pack.externals for pack in candidates),
    )
    return loaded, record


def externals_for(relative_path: str) -> dict[str, str]:
    path = PurePosixPath(relative_path)
    parent = path.parent.as_posix()
    return {
        "filename": path.name,
        "filepath": "" if parent == "." else parent,
        "extension": path.suffix.lower(),
    }


def _parse_matches(
    stdout: str,
    rules: LoadedRules,
) -> tuple[tuple[YaraMatch, ...], bool]:
    matches: list[YaraMatch] = []
    seen: set[tuple[str, str]] = set()
    truncated = False
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except ValueError:
            continue
        found = payload.get("rules") if isinstance(payload, dict) else None
        if not isinstance(found, list):
            continue
        for rule in found:
            if not isinstance(rule, dict):
                continue
            namespace = rule.get("namespace")
            identifier = rule.get("identifier")
            if not isinstance(namespace, str) or not isinstance(identifier, str):
                continue
            owner = rules.by_namespace.get(namespace)
            if owner is None or (namespace, identifier) in seen:
                continue
            pack, local_namespace = owner
            seen.add((namespace, identifier))
            if len(matches) >= MAX_MATCHES_PER_FILE:
                truncated = True
                continue
            description = None
            meta = rule.get("meta")
            if isinstance(meta, list):
                for item in meta:
                    if (
                        isinstance(item, list) and len(item) == 2
                        and item[0] == "description" and isinstance(item[1], str)
                    ):
                        description = item[1][:MAX_DESCRIPTION_CHARS]
                        break
            tags = rule.get("tags")
            matches.append(
                YaraMatch(
                    pack=pack.id,
                    kind=pack.kind,
                    namespace=local_namespace,
                    rule=identifier,
                    severity=pack.severity(local_namespace, identifier),
                    description=description,
                    tags=tuple(
                        t[:64] for t in tags if isinstance(t, str)
                    )[:16] if isinstance(tags, list) else (),
                )
            )
    matches.sort(key=lambda m: (SEVERITY_ORDER[m.severity], m.pack, m.namespace, m.rule))
    return tuple(matches), truncated


def scan_file(
    group: AnalysisGroup,
    scan_root: Path,
    rules: LoadedRules,
    *,
    executable: str,
    timeout_seconds: float,
) -> YaraFileResult:
    entry = group.representative
    target = scan_root / entry.relative_path
    reused = group.reused_paths
    if target.is_symlink() or not target.is_file():
        return YaraFileResult(
            entry.relative_path, reused, (), False, False, False,
            "not a regular file", 0.0,
        )
    yr_timeout = max(1, int(timeout_seconds))
    command = [
        executable, "scan",
        "--compiled-rules", str(rules.compiled),
        str(target),
        "--output-format", "ndjson",
        "--print-namespace", "--print-meta", "--print-tags",
        "--disable-console-logs",
        "--timeout", str(yr_timeout),
        "--max-matches-per-pattern", str(MAX_MATCHES_PER_PATTERN),
        "--threads", "1",
        *_define_arguments(externals_for(entry.relative_path)),
    ]
    execution = run_command(
        command,
        timeout_seconds=yr_timeout + 10,
        max_output_bytes=2_000_000,
        env=YR_ENV,
        stoppable=True,
    )
    matches, truncated = _parse_matches(execution.stdout, rules)
    error = None
    timed_out = execution.timed_out
    if execution.stopped:
        error = stop_request.STOPPED_MESSAGE
    elif execution.return_code != 0:
        detail = _first_error(execution)
        timed_out = timed_out or "timeout" in detail.lower()
        error = "timed out" if timed_out else f"yr failed: {detail}"
    return YaraFileResult(
        relative_path=entry.relative_path,
        reused_for=reused,
        matches=matches,
        complete=error is None and not execution.output_truncated,
        timed_out=timed_out,
        stopped_by_user=execution.stopped,
        error=error or ("output was truncated" if execution.output_truncated else None),
        duration_seconds=execution.duration_seconds,
        matches_truncated=truncated,
    )


def eligible_entries(entries: list[InventoryEntry]) -> list[InventoryEntry]:
    return [
        entry
        for entry in entries
        if entry.kind == EntryKind.REGULAR_FILE and entry.state == EntryState.INVENTORIED
    ]


def _groups_for(entries: list[InventoryEntry], uses_externals: bool) -> tuple[AnalysisGroup, ...]:
    if not uses_externals:
        return group_entries_by_sha256(entries)
    # Rules that read the file name can match one copy and not another.
    return tuple(
        AnalysisGroup(representative=entry, entries=(entry,))
        for entry in sorted(entries, key=lambda e: e.relative_path)
    )


def _match_message(result: YaraFileResult) -> str:
    worst = result.matches[0]
    others = len(result.matches) - 1
    more = f" (+{others} more)" if others else ""
    copies = f" (+{len(result.reused_for)} identical copies)" if result.reused_for else ""
    return (
        f"YARA-X match ({worst.severity}): {short_path(result.relative_path)}{copies}: "
        f"{worst.pack}/{worst.rule}{more}"
    )


def run_yara_stage(
    entries: list[InventoryEntry],
    scan_root: Path,
    *,
    executable: str,
    app_version: str,
    packs_root: Path = PACKS_MOUNT,
    local_root: Path | None = LOCAL_PACKS_MOUNT,
    workers: int = 1,
    file_timeout_seconds: float = YARA_FILE_TIMEOUT_SECONDS,
    total_timeout_seconds: float = YARA_TOTAL_TIMEOUT_SECONDS,
    on_message: ProgressMessage | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> YaraBatchResult:
    started = clock()
    say = on_message or (lambda message: None)
    eligible = eligible_entries(entries)
    work_dir = Path(tempfile.mkdtemp(prefix="mantha-yara-"))
    try:
        try:
            rules, record = compile_rules(
                packs_root, work_dir, executable=executable, app_version=app_version,
                local_root=local_root,
            )
        except RulesUnavailable as exc:
            return YaraBatchResult(
                status="unavailable", complete=False, error=str(exc),
                eligible_files=len(eligible),
            )
        except RulesError as exc:
            return YaraBatchResult(
                status="error", complete=False, error=str(exc),
                eligible_files=len(eligible),
                duration_seconds=round(clock() - started, 3),
            )

        verified = record.get("verified") is True
        batch = YaraBatchResult(
            status="completed",
            complete=True,
            bundle=_bundle_dict(rules.bundle, verified) if rules.bundle else None,
            packs=[_pack_dict(pack, True) for pack in rules.packs]
            + [
                _pack_dict(pack, False, reason["reason"])
                for reason in rules.skipped
                for pack in (rules.bundle.packs if rules.bundle else ())
                if pack.id == reason["id"]
            ],
            rule_count=sum(len(pack.rules) for pack in rules.packs),
            eligible_files=len(eligible),
            workers=max(1, workers),
        )
        local_count = sum(pack.is_local for pack in rules.packs)
        origin = []
        if rules.bundle:
            origin.append(
                f"bundle {rules.bundle.bundle_version}{'' if verified else ', unsigned'}"
            )
        if local_count:
            origin.append(f"{local_count} of your own rule file{'s' if local_count != 1 else ''}")
        say(
            f"YARA-X loaded {batch.rule_count} rules from "
            f"{len(rules.packs)} pack{'s' if len(rules.packs) != 1 else ''} "
            f"({'; '.join(origin)})."
        )
        for reason in rules.skipped:
            say(f"YARA-X left out pack {reason['id']}: {reason['reason']}")

        in_size = [
            e for e in eligible
            if isinstance(e.size_bytes, int) and e.size_bytes <= YARA_MAX_FILE_BYTES
        ]
        too_big = len(eligible) - len(in_size)
        groups = _groups_for(in_size, rules.uses_externals)
        batch.unique_files = len(groups)
        batch.duplicate_scans_avoided = len(in_size) - len(groups)
        batch.skipped_due_to_size = too_big

        _scan_groups(
            groups, scan_root, rules, batch,
            executable=executable,
            file_timeout_seconds=file_timeout_seconds,
            total_timeout_seconds=total_timeout_seconds,
            started=started, clock=clock, say=say,
        )

        batch.complete = (
            batch.skipped_due_to_timeout == 0
            and batch.failed_files == 0
            and batch.skipped_due_to_size == 0
        )
        if not batch.complete:
            batch.status = "incomplete"
            batch.error = _issues(batch)
        batch.duration_seconds = round(clock() - started, 3)
        return batch
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def _scan_groups(
    groups: tuple[AnalysisGroup, ...],
    scan_root: Path,
    rules: LoadedRules,
    batch: YaraBatchResult,
    *,
    executable: str,
    file_timeout_seconds: float,
    total_timeout_seconds: float,
    started: float,
    clock: Callable[[], float],
    say: ProgressMessage,
) -> None:
    deadline = started + total_timeout_seconds
    pending = list(groups)
    pending.reverse()  # pop() from the end keeps path order
    running: dict[Future[YaraFileResult], AnalysisGroup] = {}
    lock = threading.Lock()
    last_progress = clock()
    total = len(groups)

    with ThreadPoolExecutor(max_workers=batch.workers) as pool:
        while pending or running:
            while pending and len(running) < batch.workers:
                remaining = deadline - clock()
                if stop_request.requested() or remaining < 1:
                    break
                group = pending.pop()
                future = pool.submit(
                    scan_file, group, scan_root, rules,
                    executable=executable,
                    timeout_seconds=min(file_timeout_seconds, remaining),
                )
                running[future] = group
            if not running:
                break
            done, _ = wait(running, timeout=1.0, return_when=FIRST_COMPLETED)
            for future in done:
                group = running.pop(future)
                try:
                    result = future.result()
                except OSError as exc:
                    result = YaraFileResult(
                        group.representative.relative_path, group.reused_paths, (),
                        False, False, False, f"yr could not start: {type(exc).__name__}", 0.0,
                    )
                with lock:
                    batch.results.append(result)
                    batch.scanned_files += 1
                    if not result.complete:
                        if result.stopped_by_user:
                            batch.stopped_files += 1
                        elif result.timed_out:
                            batch.timed_out_files += 1
                        batch.failed_files += 1
                if result.matches:
                    say(_match_message(result))
            now = clock()
            if now - last_progress >= PROGRESS_INTERVAL_SECONDS and (pending or running):
                last_progress = now
                say(
                    f"YARA-X scanned {batch.scanned_files:,} of {total:,} files "
                    f"({len(batch.matched_files)} with matches)."
                )

    batch.skipped_due_to_timeout = sum(
        len(group.entries) for group in pending
    )
    batch.results.sort(key=lambda r: r.relative_path)


def _issues(batch: YaraBatchResult) -> str:
    issues: list[str] = []
    if batch.skipped_due_to_timeout:
        n = batch.skipped_due_to_timeout
        reason = (
            stop_request.STOPPED_MESSAGE
            if stop_request.requested()
            else "the YARA-X total-time limit was reached"
        )
        issues.append(f"{n} {'file was' if n == 1 else 'files were'} not scanned because {reason}")
    if batch.timed_out_files:
        n = batch.timed_out_files
        issues.append(f"{n} {'file' if n == 1 else 'files'} timed out")
    other = batch.failed_files - batch.timed_out_files - batch.stopped_files
    if other:
        issues.append(f"{other} {'scan' if other == 1 else 'scans'} failed")
    if batch.stopped_files:
        n = batch.stopped_files
        issues.append(f"{n} {'scan was' if n == 1 else 'scans were'} stopped by the user")
    if batch.skipped_due_to_size:
        n = batch.skipped_due_to_size
        issues.append(
            f"{n} {'file is' if n == 1 else 'files are'} larger than "
            f"{YARA_MAX_FILE_BYTES // 1024**3} GiB and {'was' if n == 1 else 'were'} not scanned"
        )
    return "; ".join(issues)


def summary_message(batch: YaraBatchResult) -> str:
    if batch.status in ("unavailable", "error"):
        return f"YARA-X: {batch.error}."
    counts = batch.severity_counts()
    took = format_duration(batch.duration_seconds or 0.0)
    if not batch.matched_files:
        found = "no matches"
    else:
        found = ", ".join(
            f"{counts[s]} {s}" for s in ("threat", "suspicious", "info") if counts[s]
        )
    return f"YARA-X scanned {batch.scanned_files:,} files in {took}: {found}."
