from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from .case_summary import DEFAULT_RESULTS, clean
from .file_progress import format_size

# The file kinds capa and FLOSS analyze, so the ones worth identifying by
# hash. Taken from routing_class rather than the extension, because game
# folders are full of libraries under names like .dle and .rne.
ANALYZED_CLASSES = frozenset({"pe_executable", "pe_dll", "elf"})
PREFIX_LENGTH = 12
MAX_LINE_BYTES = 1_000_000


@dataclass(frozen=True, slots=True)
class FileRecord:
    relative_path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class Group:
    """One unique file, with every path it appears at."""

    sha256: str
    size_bytes: int
    paths: tuple[str, ...]

    @property
    def name(self) -> str:
        return self.paths[0]

    @property
    def copies(self) -> int:
        return len(self.paths) - 1


@dataclass(frozen=True, slots=True)
class Reference:
    """A published file we can recognise: a vendor build or a crack component."""

    sha256: str
    name: str
    source: str
    kind: str

    @property
    def label(self) -> str:
        suffix = {
            "vendor": "vendor build",
            "crack-component": "known crack component",
        }.get(self.kind, self.kind)
        return f"{self.source} ({suffix})"


def read_executables(case_dir: Path) -> list[FileRecord]:
    """Inventoried executables from a case's files.jsonl."""

    path = case_dir / "files.jsonl"
    records: list[FileRecord] = []
    try:
        handle = path.open("r", encoding="utf-8", errors="replace")
    except OSError:
        return records
    with handle:
        for line in handle:
            if len(line) > MAX_LINE_BYTES:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if (
                not isinstance(entry, dict)
                or entry.get("kind") != "regular_file"
                or entry.get("state") != "inventoried"
                or entry.get("routing_class") not in ANALYZED_CLASSES
            ):
                continue
            sha256 = entry.get("sha256")
            size = entry.get("size_bytes")
            relative_path = entry.get("relative_path")
            if (
                not isinstance(sha256, str)
                or not isinstance(relative_path, str)
                or not isinstance(size, int)
                or isinstance(size, bool)
            ):
                continue
            records.append(FileRecord(relative_path, sha256, size))
    return records


def group_by_hash(records: Iterable[FileRecord]) -> list[Group]:
    """Collapse identical files, biggest first; identical copies are one entry."""

    grouped: dict[str, list[FileRecord]] = {}
    for record in records:
        grouped.setdefault(record.sha256, []).append(record)
    groups = [
        Group(
            sha256=sha256,
            size_bytes=items[0].size_bytes,
            paths=tuple(sorted(item.relative_path for item in items)),
        )
        for sha256, items in grouped.items()
    ]
    groups.sort(key=lambda group: (-group.size_bytes, group.name))
    return groups


def load_reference(path: Path) -> dict[str, Reference]:
    """Read a reference list: one JSON object per line."""

    found: dict[str, Reference] = {}
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip() or len(line) > MAX_LINE_BYTES:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            sha256 = entry.get("sha256") if isinstance(entry, dict) else None
            if not isinstance(sha256, str):
                continue
            found[sha256.lower()] = Reference(
                sha256=sha256.lower(),
                name=str(entry.get("name", "")),
                source=str(entry.get("source", "unknown source")),
                kind=str(entry.get("kind", "vendor")),
            )
    return found


def find_cases(target: Path) -> list[Path]:
    target = target.expanduser()
    if (target / "files.jsonl").is_file() or (target / "report.json").is_file():
        return [target]
    if not target.is_dir():
        raise SystemExit(f"No case or results folder at {clean(target)}")
    return sorted(
        (path for path in target.iterdir() if (path / "files.jsonl").is_file()),
        key=lambda path: path.name,
    )


def describe(
    cases: list[Path],
    *,
    full: bool = False,
    reference: dict[str, Reference] | None = None,
) -> Iterator[str]:
    total_groups = 0
    matched = 0
    for case_dir in cases:
        groups = group_by_hash(read_executables(case_dir))
        total_groups += len(groups)
        paths = sum(len(group.paths) for group in groups)
        yield ""
        yield (
            f"{clean(case_dir.name, 60)} — {len(groups)} unique, {paths} paths"
        )
        yield ""
        for group in groups:
            digest = group.sha256 if full else group.sha256[:PREFIX_LENGTH]
            copies = (
                f"  (+{group.copies} identical cop"
                + ("y)" if group.copies == 1 else "ies)")
                if group.copies
                else ""
            )
            line = (
                f"  {format_size(group.size_bytes):>9}  {digest}  "
                f"{clean(group.name, 70)}{copies}"
            )
            if reference is not None:
                known = reference.get(group.sha256.lower())
                if known is not None:
                    matched += 1
                    line += f"\n        └─ {clean(known.label, 80)}"
            yield line
    yield ""
    if reference is not None:
        yield (
            f"{matched} of {total_groups} unique executables matched the "
            f"reference list ({len(reference)} entries)."
        )
    else:
        yield (
            f"{total_groups} unique executables across {len(cases)} "
            + ("case." if len(cases) == 1 else "cases.")
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="reference-check.sh",
        description=(
            "List the executables a case inventoried, and optionally say "
            "which ones match a list of published files."
        ),
    )
    parser.add_argument(
        "target",
        nargs="?",
        help=f"a case folder or a results folder (default: {DEFAULT_RESULTS})",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="print whole SHA-256 hashes instead of the first 12 characters",
    )
    parser.add_argument(
        "--check",
        metavar="FILE",
        help="a reference list (JSON Lines) to match the files against",
    )
    args = parser.parse_args(argv)

    cases = find_cases(Path(args.target) if args.target else DEFAULT_RESULTS)
    if not cases:
        raise SystemExit("No cases with a files.jsonl were found.")

    reference = None
    if args.check:
        reference_path = Path(args.check).expanduser()
        if not reference_path.is_file():
            raise SystemExit(f"No reference list at {clean(reference_path)}")
        reference = load_reference(reference_path)

    for line in describe(cases, full=args.full, reference=reference):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
