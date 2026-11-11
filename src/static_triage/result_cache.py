from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from .capa import CapaCapability, CapaResult, CapaStatus
from .floss import EMULATION, FlossResult, FlossStatus, FlossString
from .parallel import MAX_TIMEOUT_ATTEMPTS, escalated_timeout

__all__ = ["escalated_timeout"]

# Results of slow analyzers (capa, FLOSS), saved by the file's SHA-256 so a
# later scan of an identical file can reuse them. The host builds the cache
# from finished cases (report.json plus files.jsonl); the scan container only
# reads it, through a read-only mount. A changed file has a different hash,
# so it is never matched to an old result.

CACHE_SCHEMA = 1
CACHE_MOUNT = Path("/cache")
ANALYZERS = ("capa", "floss")
MAX_ENTRY_BYTES = 16 * 1024 * 1024
MAX_REPORT_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_FILES_JSONL_BYTES = 512 * 1024 * 1024
MAX_CASES_PER_INGEST = 50
MAX_CAPABILITIES = 5_000
MAX_STRINGS = 100_000
MAX_TEXT = 65_536

MAX_TIMEOUT_CASES = 10

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
CASE_ID_PATTERN = re.compile(r"^case-\d{8}T\d{6}Z-[0-9a-f]{8}$")


class CacheError(ValueError):
    """A cache entry or case that can't be used."""


def cache_home() -> Path:
    override = os.environ.get("MANTHA_RAY_CACHE_HOME")
    if override:
        return Path(override).expanduser()
    data = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(data) / "mantha-ray" / "cache"


def entry_path(root: Path, analyzer: str, sha256: str) -> Path:
    if analyzer not in ANALYZERS or not SHA256_PATTERN.fullmatch(sha256):
        raise CacheError("invalid cache key")
    return root / analyzer / sha256[:2] / f"{sha256}.json"


def timeout_path(root: Path, analyzer: str, sha256: str) -> Path:
    if analyzer not in ANALYZERS or not SHA256_PATTERN.fullmatch(sha256):
        raise CacheError("invalid cache key")
    return root / "timeouts" / analyzer / sha256[:2] / f"{sha256}.json"


def load_more_time(root: Path | None, analyzer: str, hashes: Iterable[str]) -> dict[str, int]:
    """Earlier per-file timeouts for these hashes, as {sha256: attempts}."""

    found: dict[str, int] = {}
    if root is None or not (root / "timeouts").is_dir():
        return found
    for sha256 in set(hashes):
        try:
            data = _read_json(timeout_path(root, analyzer, sha256), 65_536)
        except (OSError, ValueError, UnicodeDecodeError):
            continue
        attempts = data.get("attempts") if isinstance(data, dict) else None
        if isinstance(attempts, int) and not isinstance(attempts, bool) and attempts > 0:
            found[sha256] = min(attempts, MAX_TIMEOUT_ATTEMPTS)
    return found


def _record_timeout(root: Path, analyzer: str, sha256: str, case_id: str,
                    timeout_seconds: Any) -> None:
    path = timeout_path(root, analyzer, sha256)
    data: dict[str, Any] = {"attempts": 0, "cases": []}
    try:
        existing = _read_json(path, 65_536)
        if (
            isinstance(existing, dict)
            and isinstance(existing.get("attempts"), int)
            and isinstance(existing.get("cases"), list)
        ):
            data = existing
    except (OSError, ValueError, UnicodeDecodeError):
        pass
    if case_id in data["cases"]:
        return
    data["attempts"] = int(data["attempts"]) + 1
    data["cases"] = ([case_id] + [c for c in data["cases"] if isinstance(c, str)])[:MAX_TIMEOUT_CASES]
    if isinstance(timeout_seconds, (int, float)) and not isinstance(timeout_seconds, bool):
        data["last_limit_seconds"] = float(timeout_seconds)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, sort_keys=True).encode("utf-8")
    handle = tempfile.NamedTemporaryFile(dir=path.parent, prefix=".tmp-", delete=False)
    try:
        with handle:
            handle.write(payload)
        os.replace(handle.name, path)
    except OSError:
        Path(handle.name).unlink(missing_ok=True)
        raise


# --- validation shared by both sides -----------------------------------------


def _text(value: Any, *, optional: bool = False, limit: int = MAX_TEXT) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or len(value) > limit:
        raise CacheError("invalid text field")
    return value


def _count(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CacheError("invalid count")
    return value


def _number(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise CacheError("invalid number")
    return float(value)


def _ids(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 200:
        raise CacheError("invalid id list")
    return tuple(_text(item, limit=200) for item in value)  # type: ignore[misc]


def _capabilities(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_CAPABILITIES:
        raise CacheError("invalid capabilities")
    cleaned = []
    for item in value:
        if not isinstance(item, dict):
            raise CacheError("invalid capability")
        cleaned.append({
            "name": _text(item.get("name"), limit=1_000),
            "namespace": _text(item.get("namespace"), optional=True, limit=1_000),
            "match_count": _count(item.get("match_count")),
            "attack_ids": list(_ids(item.get("attack_ids", []))),
            "mbc_ids": list(_ids(item.get("mbc_ids", []))),
        })
    return cleaned


def _strings(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_STRINGS:
        raise CacheError("invalid strings")
    cleaned = []
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get("truncated"), bool):
            raise CacheError("invalid string")
        record = {
            "kind": _text(item.get("kind"), limit=100),
            "value": _text(item.get("value")),
            "encoding": _text(item.get("encoding"), optional=True, limit=100),
            "truncated": item["truncated"],
        }
        category = _text(item.get("category"), optional=True, limit=200)
        if category is not None:
            record["category"] = category
        cleaned.append(record)
    return cleaned


def _clean_entry(raw: Any, analyzer: str, sha256: str) -> dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("schema") != CACHE_SCHEMA:
        raise CacheError("unknown cache entry format")
    if raw.get("analyzer") != analyzer or raw.get("sha256") != sha256:
        raise CacheError("cache entry is for a different file")
    case_id = _text(raw.get("case_id"), limit=64)
    if not CASE_ID_PATTERN.fullmatch(case_id or ""):
        raise CacheError("invalid case id")
    entry: dict[str, Any] = {
        "schema": CACHE_SCHEMA,
        "analyzer": analyzer,
        "sha256": sha256,
        "tool_version": _text(raw.get("tool_version"), limit=200),
        "case_id": case_id,
        "analyzed_at": _text(raw.get("analyzed_at"), optional=True, limit=64),
        "relative_path": _text(raw.get("relative_path"), limit=4_096),
        "duration_seconds": _number(raw.get("duration_seconds")),
        "peak_memory_mib": _number(raw.get("peak_memory_mib")),
    }
    if analyzer == "capa":
        entry["capabilities"] = _capabilities(raw.get("capabilities"))
    else:
        if not isinstance(raw.get("strings_truncated"), bool):
            raise CacheError("invalid FLOSS entry")
        fully = raw.get("fully_scanned")
        if fully is not None and not isinstance(fully, bool):
            raise CacheError("invalid FLOSS entry")
        entry.update({
            "strings": _strings(raw.get("strings")),
            "total_strings": _count(raw.get("total_strings")),
            "strings_truncated": raw["strings_truncated"],
            "fully_scanned": fully,
            "max_strings": _count(raw.get("max_strings")),
            "max_string_chars": _count(raw.get("max_string_chars")),
        })
    return entry


def _read_json(path: Path, limit: int) -> Any:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise CacheError(f"{path.name} is too large")
    return json.loads(data.decode("utf-8"))


# --- scan container: look up results ------------------------------------------


def _cached_from(entry: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "case_id": entry["case_id"],
        "analyzed_at": entry["analyzed_at"],
        "relative_path": entry["relative_path"],
        "duration_seconds": entry["duration_seconds"],
        "tool_version": entry["tool_version"],
    }


def _load(root: Path | None, analyzer: str, hashes: Iterable[str]) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    if root is None or not root.is_dir():
        return found
    for sha256 in set(hashes):
        try:
            path = entry_path(root, analyzer, sha256)
            found[sha256] = _clean_entry(_read_json(path, MAX_ENTRY_BYTES), analyzer, sha256)
        except (OSError, ValueError, UnicodeDecodeError):
            # Missing, unreadable or invalid entries are simply not reused.
            continue
    return found


def load_capa(
    root: Path | None, hashes: Iterable[str], *, tool_version: str | None,
) -> dict[str, CapaResult]:
    """Earlier complete capa results for these hashes, made by this capa version."""

    if not tool_version:
        return {}
    results = {}
    for sha256, entry in _load(root, "capa", hashes).items():
        if entry["tool_version"] != tool_version:
            continue
        results[sha256] = CapaResult(
            status=CapaStatus.COMPLETED,
            complete=True,
            relative_path=entry["relative_path"],
            return_code=0,
            capabilities=tuple(
                CapaCapability(
                    name=item["name"],
                    namespace=item["namespace"],
                    match_count=item["match_count"],
                    attack_ids=tuple(item["attack_ids"]),
                    mbc_ids=tuple(item["mbc_ids"]),
                )
                for item in entry["capabilities"]
            ),
            timed_out=False,
            output_truncated=False,
            duration_seconds=0.0,
            stdout="",
            stderr="",
            cached_from=_cached_from(entry),
        )
    return results


def load_floss(
    root: Path | None,
    hashes: Iterable[str],
    *,
    tool_version: str | None,
    max_strings: int,
    max_string_chars: int,
) -> dict[str, FlossResult]:
    """Earlier complete FLOSS decoding results made with the same version and limits."""

    if not tool_version:
        return {}
    results = {}
    for sha256, entry in _load(root, "floss", hashes).items():
        if (
            entry["tool_version"] != tool_version
            or entry["max_strings"] != max_strings
            or entry["max_string_chars"] != max_string_chars
        ):
            continue
        results[sha256] = FlossResult(
            status=FlossStatus.COMPLETED,
            complete=True,
            relative_path=entry["relative_path"],
            return_code=0,
            strings=tuple(
                FlossString(
                    kind=item["kind"],
                    value=item["value"],
                    encoding=item["encoding"],
                    truncated=item["truncated"],
                    category=item.get("category"),
                )
                for item in entry["strings"]
            ),
            total_strings=entry["total_strings"],
            strings_truncated=entry["strings_truncated"],
            timed_out=False,
            output_truncated=False,
            duration_seconds=0.0,
            stdout="",
            stderr="",
            mode=EMULATION,
            fully_scanned=entry["fully_scanned"],
            cached_from=_cached_from(entry),
        )
    return results


# --- host: build the cache from finished cases ---------------------------------


def _file_hashes(case_dir: Path) -> dict[str, str]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(case_dir / "files.jsonl", flags)
    hashes: dict[str, str] = {}
    read = 0
    with os.fdopen(fd, "rb") as handle:
        for line in handle:
            read += len(line)
            if read > MAX_FILES_JSONL_BYTES:
                raise CacheError("files.jsonl is too large")
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if not isinstance(record, dict):
                continue
            path, sha256 = record.get("relative_path"), record.get("sha256")
            if (
                record.get("kind") == "regular_file"
                and record.get("state") == "inventoried"
                and isinstance(path, str)
                and isinstance(sha256, str)
                and SHA256_PATTERN.fullmatch(sha256)
            ):
                hashes[path] = sha256
    return hashes


def _tool_versions(report: Mapping[str, Any]) -> dict[str, str]:
    versions = {}
    for tool in report.get("tools") or []:
        if (
            isinstance(tool, dict)
            and isinstance(tool.get("name"), str)
            and isinstance(tool.get("version"), str)
            and tool.get("available") is True
        ):
            versions[tool["name"]] = tool["version"]
    return versions


def _write_entry(root: Path, entry: dict[str, Any]) -> bool:
    path = entry_path(root, entry["analyzer"], entry["sha256"])
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_ENTRY_BYTES:
        return False
    handle = tempfile.NamedTemporaryFile(dir=path.parent, prefix=".tmp-", delete=False)
    try:
        with handle:
            handle.write(data)
        os.replace(handle.name, path)
    except OSError:
        Path(handle.name).unlink(missing_ok=True)
        raise
    return True


def _entries_from_case(case_dir: Path) -> list[dict[str, Any]]:
    report = _read_json(case_dir / "report.json", MAX_REPORT_BYTES)
    manifest = _read_json(case_dir / "manifest.json", MAX_MANIFEST_BYTES)
    for name, data in (("report.json", report), ("manifest.json", manifest)):
        if not isinstance(data, dict) or data.get("case_id") != case_dir.name:
            raise CacheError(f"{name} doesn't belong to this case")
    hashes = _file_hashes(case_dir)
    versions = _tool_versions(manifest)
    limits = manifest.get("limits") if isinstance(manifest.get("limits"), dict) else {}
    analyzers = report.get("analyzers") if isinstance(report.get("analyzers"), dict) else {}
    entries: list[dict[str, Any]] = []
    timeouts: list[tuple[str, str, Any]] = []
    for analyzer, tool in (("capa", "capa"), ("floss", "floss")):
        version = versions.get(tool)
        batch = analyzers.get(analyzer)
        if not version or not isinstance(batch, dict):
            continue
        for result in batch.get("results") or []:
            if not isinstance(result, dict) or result.get("cached_from"):
                continue
            path = result.get("relative_path")
            # Only files this case actually inventoried, under their own hash.
            sha256 = hashes.get(path) if isinstance(path, str) else None
            if sha256 is None:
                continue
            if (
                result.get("timed_out") is True
                and not result.get("stopped_at_budget_end")
                and not result.get("stopped_by_user")
            ):
                # A real per-file timeout: give it more time next scan.
                timeouts.append((analyzer, sha256, result.get("timeout_seconds")))
                continue
            if (
                result.get("complete") is not True
                or result.get("status") != "completed"
                or (analyzer == "floss" and result.get("mode") != EMULATION)
            ):
                continue
            raw = {
                "schema": CACHE_SCHEMA,
                "analyzer": analyzer,
                "sha256": sha256,
                "tool_version": version,
                "case_id": case_dir.name,
                "analyzed_at": manifest.get("completed_at"),
                "relative_path": path,
                "duration_seconds": result.get("duration_seconds"),
                "peak_memory_mib": result.get("peak_memory_mib"),
            }
            if analyzer == "capa":
                raw["capabilities"] = result.get("capabilities")
            else:
                raw.update({
                    "strings": result.get("strings"),
                    "total_strings": result.get("total_string_count"),
                    "strings_truncated": result.get("strings_truncated"),
                    "fully_scanned": result.get("fully_scanned"),
                    "max_strings": limits.get("floss_max_strings"),
                    "max_string_chars": limits.get("floss_max_string_chars"),
                })
            try:
                entries.append(_clean_entry(raw, analyzer, sha256))
            except CacheError:
                continue
    return entries, timeouts


def ingest_case(case_dir: Path, root: Path | None = None) -> int:
    """Add a finished case's complete capa and FLOSS results. Returns how many were new."""

    root = root or cache_home()
    if not CASE_ID_PATTERN.fullmatch(case_dir.name):
        raise CacheError("not a case folder")
    marker = root / "ingested" / case_dir.name
    if marker.exists():
        return 0
    entries, timeouts = _entries_from_case(case_dir)
    added = sum(_write_entry(root, entry) for entry in entries)
    for analyzer, sha256, limit in timeouts:
        try:
            _record_timeout(root, analyzer, sha256, case_dir.name, limit)
        except (OSError, CacheError):
            continue
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()
    return added


def ingest_results_directory(results_directory: Path, root: Path | None = None) -> int:
    """Ingest the newest cases in a results folder that aren't in the cache yet.

    Covers scans whose window closed before they finished: their results are
    picked up the next time a scan starts.
    """

    root = root or cache_home()
    try:
        cases = sorted(
            (path for path in results_directory.iterdir()
             if CASE_ID_PATTERN.fullmatch(path.name) and path.is_dir() and not path.is_symlink()),
            key=lambda path: path.name,
            reverse=True,
        )[:MAX_CASES_PER_INGEST]
    except OSError:
        return 0
    added = 0
    for case_dir in cases:
        if (root / "ingested" / case_dir.name).exists() or not (case_dir / "report.json").is_file():
            continue
        try:
            added += ingest_case(case_dir, root)
        except (OSError, ValueError, UnicodeDecodeError):
            continue
    return added


def status(root: Path | None = None) -> dict[str, Any]:
    root = root or cache_home()
    counts: dict[str, int] = {}
    total_bytes = 0
    for analyzer in ANALYZERS:
        count = 0
        for path in (root / analyzer).glob("??/*.json"):
            count += 1
            try:
                total_bytes += path.stat().st_size
            except OSError:
                pass
        counts[analyzer] = count
    return {"path": str(root), "entries": counts, "bytes": total_bytes}


def clear(root: Path | None = None) -> int:
    """Delete every cached result. Returns how many entries were removed."""

    root = root or cache_home()
    removed = 0
    for analyzer in ANALYZERS:
        for path in (root / analyzer).glob("??/*.json"):
            path.unlink(missing_ok=True)
            removed += 1
        for path in (root / "timeouts" / analyzer).glob("??/*.json"):
            path.unlink(missing_ok=True)
    # The "ingested" markers stay, so the cases already read aren't read
    # again: clearing really does mean those files get analyzed afresh.
    return removed
