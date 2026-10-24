from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .contract import (
    EXTERNALS,
    LOCAL_PREFIX,
    MAX_RULE_FILE,
    SEVERITIES,
    ContractError,
    PackInfo,
    _strip_comments,
    declared_rules,
    validate_pack,
)
from .store import PackInstallError, packs_home

# Your own .yar files, each kept as a one-file "local:<name>" pack under
# <packs home>/local/<name>/, in the same layout as a bundle pack. They sit
# beside the signed bundle, never inside it, so bundle updates leave them
# alone and they can't change an official rule.

MAX_LOCAL_PACKS = 50
NAMESPACE = "rules"
DEFAULT_SEVERITY = "suspicious"
INCLUDE_RE = re.compile(r"^\s*include\s+\"", re.M)

LocalCheck = Callable[[Path], dict[str, Any]]


def local_root(home: Path | None = None) -> Path:
    return (home or packs_home()) / "local"


def pack_name(filename: str) -> str:
    stem = Path(filename).stem.lower()
    name = re.sub(r"[^a-z0-9]+", "-", stem).strip("-")[:40].strip("-")
    if not name or not name[0].isalnum():
        name = f"rules-{name}".strip("-") if name else "rules"
    return name


def _uses_externals(text: str) -> list[str]:
    body = _strip_comments(text)
    # Only conditions can read externals; strings sections can't.
    conditions = " ".join(re.findall(r"condition\s*:(.*?)(?=\n\s*\}|\Z)", body, re.S))
    return [name for name in EXTERNALS if re.search(rf"\b{name}\b", conditions)]


def build_pack(
    destination: Path,
    *,
    name: str,
    text: str,
    severity: str,
    source: str,
) -> PackInfo:
    if severity not in SEVERITIES:
        raise PackInstallError(f"severity must be one of {', '.join(SEVERITIES)}")
    if len(text.encode("utf-8")) > MAX_RULE_FILE:
        raise PackInstallError(f"the rule file is larger than {MAX_RULE_FILE // 2**20} MiB")
    if INCLUDE_RE.search(_strip_comments(text)):
        raise PackInstallError(
            "the rule file uses `include`, which isn't supported here; "
            "put the rules it needs into the same file"
        )
    rules = [rule for rule, public in declared_rules(text).items() if public]
    if not rules:
        raise PackInstallError("no rules found in the file (private and global rules don't count)")

    destination.mkdir(parents=True)
    (destination / "rules").mkdir()
    (destination / "rules" / f"{NAMESPACE}.yar").write_text(text, encoding="utf-8")
    pack_id = LOCAL_PREFIX + name
    (destination / "pack.json").write_text(json.dumps({
        "format": 1,
        "id": pack_id,
        "version": 1,
        "kind": "detection",
        "editions": ["all"],
        "description": f"Your rules, added from {source[:120]} on "
                       f"{datetime.now(UTC).strftime('%Y-%m-%d')}",
        "rules": [
            {"namespace": NAMESPACE, "name": rule, "file": f"rules/{NAMESPACE}.yar",
             "source": source[:200], "licence": None}
            for rule in rules
        ],
        "externals": _uses_externals(text),
    }, indent=1) + "\n", encoding="utf-8")
    (destination / "severities.json").write_text(json.dumps({
        "format": 1,
        "severities": {f"{NAMESPACE}:{rule}": severity for rule in rules},
        "demoted": {},
        "probation": {},
    }, indent=1) + "\n", encoding="utf-8")
    try:
        return validate_pack(destination, local=True)
    except ContractError as exc:
        raise PackInstallError(f"the rule file can't be used: {exc}") from exc


def add_local(
    text: str,
    *,
    source: str,
    name: str | None = None,
    severity: str = DEFAULT_SEVERITY,
    replace: bool = False,
    compile_check: LocalCheck | None = None,
    home: Path | None = None,
) -> dict[str, Any]:
    """Add one rule file as a local pack, after it compiles on its own."""

    root = local_root(home)
    name = pack_name(name or source)
    final = root / name
    existing = list_local(home)
    if final.exists() and not replace:
        raise PackInstallError(
            f"you already have local rules named {name!r}; remove them first or choose another name"
        )
    if not final.exists() and len(existing) >= MAX_LOCAL_PACKS:
        raise PackInstallError(f"you can have up to {MAX_LOCAL_PACKS} local rule files")

    root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=root))
    try:
        pack = build_pack(staging / name, name=name, text=text, severity=severity, source=source)
        if compile_check is not None:
            compile_check(staging)
        if final.exists():
            shutil.rmtree(final)
        os.replace(staging / name, final)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return _describe(pack, final)


def remove_local(name: str, home: Path | None = None) -> None:
    root = local_root(home)
    target = root / name
    if (
        not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", name)
        or target.is_symlink()
        or not target.is_dir()
    ):
        raise PackInstallError(f"no local rules named {name!r}")
    shutil.rmtree(target)


def _describe(pack: PackInfo, directory: Path) -> dict[str, Any]:
    severities = sorted(set(pack.severities.values()), key=SEVERITIES.index)
    return {
        "name": directory.name,
        "id": pack.id,
        "rules": len(pack.rules),
        "rule_names": [key.split(":", 1)[1] for key in pack.rules][:50],
        "severity": severities[0] if len(severities) == 1 else "mixed",
        "description": pack.description,
        "externals": list(pack.externals),
    }


def list_local(home: Path | None = None) -> list[dict[str, Any]]:
    root = local_root(home)
    if not root.is_dir():
        return []
    found = []
    for directory in sorted(root.iterdir()):
        if directory.name.startswith(".") or directory.is_symlink() or not directory.is_dir():
            continue
        try:
            found.append(_describe(validate_pack(directory, local=True), directory))
        except ContractError as exc:
            found.append({"name": directory.name, "id": LOCAL_PREFIX + directory.name,
                          "error": str(exc)})
    return found


def has_local(home: Path | None = None) -> bool:
    return any("error" not in pack for pack in list_local(home))
