from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

# Bundle contract v1, as written by Mantha Hermit (docs/bundle-contract.md in
# mantha-hermit). This is an independent implementation: anything Hermit's
# `validate_bundle` rejects, this rejects too. Compiling the rules is done
# separately with YARA-X (see yara_scan.compile_rules).

FORMAT = 1
SEVERITIES = ("threat", "suspicious", "info")
KINDS = ("detection", "recognition")
EXTERNALS = ("filename", "filepath", "extension")
# The edition packs name to be loaded by this build of Mantha Ray (Hermit's
# default edition), besides "all".
EDITION = "standard"

PACK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
# User packs: "local:<name>", in a folder named <name>; never in bundles.
LOCAL_PREFIX = "local:"
NAMESPACE_RE = re.compile(r"^[A-Za-z0-9_]{1,200}$")
RULE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
EDITION_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
BUNDLE_VERSION_RE = re.compile(r"^\d{4}\.\d{1,2}\.\d{1,2}\.\d{1,4}$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
CREATED_AT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
PACK_FILES = frozenset({"pack.json", "severities.json", "rules", "pack.yarx"})
# Declared rule names, used to check pack.json against the rule text without
# compiling. A rule is listed in pack.json only if it can produce a match.
RULE_DECLARATION_RE = re.compile(
    r"^[ \t]*((?:(?:private|global)[ \t]+)*)rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)",
    re.M,
)

MAX_RULE_FILE = 8 * 2**20
MAX_JSON = 32 * 2**20
MAX_PACKS = 64
MAX_RULE_FILES = 2000


class ContractError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PackInfo:
    id: str
    version: int
    kind: str
    editions: tuple[str, ...]
    description: str
    rule_files: tuple[tuple[str, Path], ...]  # (namespace, path), sorted
    rules: tuple[str, ...]  # "namespace:rule", as listed
    externals: tuple[str, ...]
    severities: dict[str, str]
    without_severity: int
    has_yarx: bool

    @property
    def loaded_here(self) -> bool:
        return "all" in self.editions or EDITION in self.editions

    @property
    def is_local(self) -> bool:
        return self.id.startswith(LOCAL_PREFIX)

    def severity(self, namespace: str, rule: str) -> str:
        return self.severities.get(f"{namespace}:{rule}", "info")


@dataclass(frozen=True, slots=True)
class BundleInfo:
    root: Path
    bundle_version: str
    created_at: str
    min_app_version: str
    yara_x_version: str
    changes: str
    packs: tuple[PackInfo, ...]


def bundle_version_key(version: str) -> tuple[int, ...]:
    # Compared as numbers: 2026.10.22.12 is newer than 2026.10.22.2.
    if not isinstance(version, str) or not BUNDLE_VERSION_RE.match(version):
        raise ContractError(f"bad bundle version {version!r}")
    return tuple(int(part) for part in version.split("."))


def app_version_key(version: str) -> tuple[int, ...]:
    if not isinstance(version, str) or not SEMVER_RE.match(version):
        raise ContractError(f"bad app version {version!r}")
    return tuple(int(part) for part in version.split("."))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def pack_digest(pack_dir: Path) -> str:
    # One "<sha256>  <relative path>\n" line per file, sorted by path: the text
    # `sha256sum` prints. Symlinks are refused before anything is read.
    if pack_dir.is_symlink():
        raise ContractError(f"pack {pack_dir.name}: the pack folder is a symlink")
    files: list[tuple[str, Path]] = []
    for dirpath, dirnames, filenames in os.walk(pack_dir, followlinks=False):
        for name in (*dirnames, *filenames):
            path = Path(dirpath, name)
            if path.is_symlink():
                raise ContractError(
                    f"pack {pack_dir.name}: symlinks are not allowed "
                    f"({path.relative_to(pack_dir).as_posix()})"
                )
        for name in filenames:
            path = Path(dirpath, name)
            files.append((path.relative_to(pack_dir).as_posix(), path))
    files.sort()
    text = "".join(f"{sha256_file(path)}  {relative}\n" for relative, path in files)
    return hashlib.sha256(text.encode()).hexdigest()


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _load_json(path: Path) -> dict:
    _expect(path.is_file() and not path.is_symlink(), f"missing {path.name}")
    _expect(path.stat().st_size <= MAX_JSON, f"{path.name} is too large")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ContractError(f"{path.name} is not valid JSON: {exc}") from exc
    _expect(isinstance(payload, dict), f"{path.name} must be a JSON object")
    return payload


def _keys(obj: dict, where: str, required: set[str], optional: frozenset[str] = frozenset()) -> None:
    missing = required - obj.keys()
    extra = obj.keys() - required - optional
    _expect(not missing, f"{where}: missing field(s) {sorted(missing)}")
    _expect(not extra, f"{where}: unknown field(s) {sorted(extra)}")


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def declared_rules(text: str) -> dict[str, bool]:
    # rule name -> whether it can produce a match (not private or global).
    found: dict[str, bool] = {}
    for modifiers, name in RULE_DECLARATION_RE.findall(_strip_comments(text)):
        found[name] = not modifiers.strip()
    return found


def _strip_comments(text: str) -> str:
    # Enough to keep commented-out rules from counting; strings that contain
    # comment markers only affect this check, never what gets compiled.
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def validate_pack(pack_dir: Path, *, local: bool = False) -> PackInfo:
    where = f"pack {pack_dir.name}"
    _expect(pack_dir.is_dir() and not pack_dir.is_symlink(), f"{where}: must be a folder")
    for path in pack_dir.iterdir():
        _expect(not path.is_symlink(), f"{where}: symlinks are not allowed ({path.name})")
        _expect(path.name in PACK_FILES, f"{where}: unexpected file {path.name}")

    meta = _load_json(pack_dir / "pack.json")
    _keys(
        meta, f"{where}/pack.json",
        {"format", "id", "version", "kind", "editions", "rules", "externals"},
        frozenset({"description"}),
    )
    _expect(meta["format"] == FORMAT, f"{where}: pack.json format must be {FORMAT}")
    prefix = LOCAL_PREFIX if local else ""
    _expect(
        isinstance(meta["id"], str)
        and meta["id"].startswith(prefix)
        and bool(PACK_ID_RE.match(meta["id"][len(prefix):])),
        f"{where}: bad id {meta['id']!r}",
    )
    _expect(
        meta["id"] == prefix + pack_dir.name,
        f"{where}: id {meta['id']!r} doesn't match folder",
    )
    _expect(_is_int(meta["version"]) and meta["version"] >= 1, f"{where}: version must be an integer >= 1")
    _expect(meta["kind"] in KINDS, f"{where}: kind must be one of {KINDS}")
    _expect(
        isinstance(meta["editions"], list) and bool(meta["editions"])
        and all(isinstance(e, str) and EDITION_RE.match(e) for e in meta["editions"]),
        f"{where}: editions must be a non-empty list of lowercase names",
    )
    description = meta.get("description", "")
    _expect(isinstance(description, str), f"{where}: description must be text")
    _expect(
        isinstance(meta["externals"], list)
        and all(isinstance(e, str) for e in meta["externals"])
        and set(meta["externals"]) <= set(EXTERNALS),
        f"{where}: externals must come from {EXTERNALS}",
    )
    _expect(isinstance(meta["rules"], list), f"{where}: rules must be a list")

    rules_dir = pack_dir / "rules"
    _expect(rules_dir.is_dir() and not rules_dir.is_symlink(), f"{where}: missing rules/")
    files: dict[str, Path] = {}
    for path in rules_dir.iterdir():
        _expect(
            path.is_file() and not path.is_symlink() and path.suffix == ".yar"
            and bool(NAMESPACE_RE.match(path.stem)),
            f"{where}: unexpected entry rules/{path.name}",
        )
        _expect(path.stat().st_size <= MAX_RULE_FILE, f"{where}: rules/{path.name} is too large")
        files[path.stem] = path
    _expect(len(files) <= MAX_RULE_FILES, f"{where}: too many rule files")

    keys: list[str] = []
    for index, rule in enumerate(meta["rules"]):
        w = f"{where}/pack.json rules[{index}]"
        _expect(isinstance(rule, dict), f"{w}: must be an object")
        _keys(rule, w, {"namespace", "name", "file", "source", "licence"})
        _expect(
            isinstance(rule["namespace"], str) and rule["namespace"] in files,
            f"{w}: no rule file for namespace {rule['namespace']!r}",
        )
        _expect(rule["file"] == f"rules/{rule['namespace']}.yar", f"{w}: file must be rules/<namespace>.yar")
        _expect(isinstance(rule["name"], str) and bool(RULE_NAME_RE.match(rule["name"])), f"{w}: bad rule name")
        for field in ("source", "licence"):
            _expect(rule[field] is None or isinstance(rule[field], str), f"{w}: {field} must be text or null")
        key = f"{rule['namespace']}:{rule['name']}"
        _expect(key not in keys, f"{w}: duplicate rule {key}")
        keys.append(key)
    key_set = set(keys)

    severity_doc = _load_json(pack_dir / "severities.json")
    _keys(severity_doc, f"{where}/severities.json", {"format", "severities", "demoted", "probation"})
    _expect(severity_doc["format"] == FORMAT, f"{where}: severities.json format must be {FORMAT}")
    for field in ("severities", "demoted", "probation"):
        _expect(isinstance(severity_doc[field], dict), f"{where}: severities.json {field} must be an object")
        unknown = set(severity_doc[field]) - key_set
        _expect(
            not unknown,
            f"{where}: severities.json {field} names rules not in pack.json: {sorted(unknown)[:3]}",
        )
    severities = severity_doc["severities"]
    _expect(all(v in SEVERITIES for v in severities.values()), f"{where}: severities must be one of {SEVERITIES}")
    _expect(all(isinstance(v, str) for v in severity_doc["demoted"].values()), f"{where}: demoted reasons must be text")
    _expect(
        all(isinstance(v, str) and DATE_RE.match(v) for v in severity_doc["probation"].values()),
        f"{where}: probation dates must be YYYY-MM-DD",
    )
    for key in severity_doc["probation"]:
        _expect(severities.get(key, "info") == "info", f"{where}: {key} is on probation but not info")

    for namespace, path in files.items():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ContractError(f"{where}: rules/{path.name} is not UTF-8") from exc
        declared = declared_rules(text)
        for key in keys:
            ns, name = key.split(":", 1)
            if ns != namespace:
                continue
            _expect(name in declared, f"{where}: pack.json lists {key}, which isn't in rules/{path.name}")
            _expect(declared[name], f"{where}: pack.json lists {key}, which is private or global")

    return PackInfo(
        id=meta["id"],
        version=meta["version"],
        kind=meta["kind"],
        editions=tuple(meta["editions"]),
        description=description,
        rule_files=tuple(sorted(files.items())),
        rules=tuple(keys),
        externals=tuple(meta["externals"]),
        severities=dict(severities),
        without_severity=len(key_set - set(severities)),
        has_yarx=(pack_dir / "pack.yarx").is_file(),
    )


def validate_bundle(root: Path) -> BundleInfo:
    _expect(root.is_dir() and not root.is_symlink(), "bundle: not a folder")
    for path in root.iterdir():
        _expect(
            path.name in ("manifest.json", "packs") and not path.is_symlink(),
            f"bundle: unexpected entry {path.name}",
        )
    m = _load_json(root / "manifest.json")
    _keys(
        m, "manifest.json",
        {"format", "bundle_version", "created_at", "min_app_version",
         "yara_x_version", "packs", "sources", "changes"},
    )
    _expect(m["format"] == FORMAT, f"manifest.json: format must be {FORMAT}")
    _expect(
        isinstance(m["bundle_version"], str) and bool(BUNDLE_VERSION_RE.match(m["bundle_version"])),
        "manifest.json: bundle_version must look like 2026.10.25.1",
    )
    _expect(
        isinstance(m["created_at"], str) and bool(CREATED_AT_RE.match(m["created_at"])),
        "manifest.json: created_at must be a UTC timestamp like 2026-10-25T03:00:00Z",
    )
    _expect(
        isinstance(m["min_app_version"], str) and bool(SEMVER_RE.match(m["min_app_version"])),
        "manifest.json: min_app_version must be like 0.3.0",
    )
    _expect(isinstance(m["yara_x_version"], str), "manifest.json: yara_x_version must be text")
    _expect(isinstance(m["changes"], str), "manifest.json: changes must be text")
    _expect(isinstance(m["sources"], list), "manifest.json: sources must be a list")
    for index, source in enumerate(m["sources"]):
        _expect(isinstance(source, dict), f"manifest.json sources[{index}]: must be an object")
        _keys(source, f"manifest.json sources[{index}]", {"name", "url", "revision", "licence"})
        _expect(
            all(v is None or isinstance(v, str) for v in source.values()),
            f"manifest.json sources[{index}]: values must be text or null",
        )
    _expect(isinstance(m["packs"], list), "manifest.json: packs must be a list")
    _expect(len(m["packs"]) <= MAX_PACKS, "manifest.json: too many packs")

    packs_dir = root / "packs"
    _expect(packs_dir.is_dir() and not packs_dir.is_symlink(), "bundle: missing packs/")
    listed: dict[str, dict] = {}
    for index, pack in enumerate(m["packs"]):
        _expect(isinstance(pack, dict), f"manifest.json packs[{index}]: must be an object")
        _keys(pack, f"manifest.json packs[{index}]", {"id", "version", "sha256"})
        _expect(
            isinstance(pack["id"], str) and bool(PACK_ID_RE.match(pack["id"])),
            f"manifest.json packs[{index}]: bad id (local: packs never ship in bundles)",
        )
        _expect(pack["id"] not in listed, f"manifest.json: pack {pack['id']} listed twice")
        _expect(
            isinstance(pack["sha256"], str) and bool(re.fullmatch(r"[0-9a-f]{64}", pack["sha256"])),
            f"manifest.json packs[{index}]: sha256 must be 64 lowercase hex digits",
        )
        listed[pack["id"]] = pack
    on_disk = {path.name for path in packs_dir.iterdir()}
    _expect(
        on_disk == set(listed),
        f"bundle: packs/ ({sorted(on_disk)}) doesn't match manifest ({sorted(listed)})",
    )

    packs = []
    for pack_id, pack in sorted(listed.items()):
        pack_dir = packs_dir / pack_id
        _expect(pack_dir.is_dir() and not pack_dir.is_symlink(), f"bundle: packs/{pack_id} must be a folder")
        _expect(
            pack_digest(pack_dir) == pack["sha256"],
            f"bundle: packs/{pack_id} doesn't match its sha256 in manifest.json",
        )
        info = validate_pack(pack_dir)
        _expect(info.version == pack["version"], f"bundle: packs/{pack_id} version differs from manifest.json")
        packs.append(info)

    return BundleInfo(
        root=root,
        bundle_version=m["bundle_version"],
        created_at=m["created_at"],
        min_app_version=m["min_app_version"],
        yara_x_version=m["yara_x_version"],
        changes=m["changes"],
        packs=tuple(packs),
    )
