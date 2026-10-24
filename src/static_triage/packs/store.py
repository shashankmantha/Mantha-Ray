from __future__ import annotations

import json
import os
import shutil
import tarfile
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import __version__
from .contract import (
    BundleInfo,
    ContractError,
    app_version_key,
    bundle_version_key,
    sha256_file,
    validate_bundle,
)
from .signing import SignatureError, parse_trusted_comment, verify_file

# Installed rule packs live outside the repository, per user:
#   <home>/state.json                    what is installed; never inside a bundle
#   <home>/installs/<version>/bundle/    the unpacked bundle (manifest.json, packs/)
#   <home>/installs/<version>/install.json
# The scan container gets the current install folder mounted read-only.

PUBLIC_KEY_PATH = Path(__file__).with_name("minisign.pub")
MAX_BUNDLE_BYTES = 256 * 2**20
MAX_UNPACKED_BYTES = 4 * MAX_BUNDLE_BYTES
MAX_MEMBERS = 50_000
KEEP_INSTALLS = 3
STALE_AFTER_DAYS = 30

CompileCheck = Callable[[Path], dict[str, Any]]


class PackInstallError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Installed:
    version: str
    verified: bool
    directory: Path
    installed_at: str
    created_at: str | None


def packs_home() -> Path:
    override = os.environ.get("MANTHA_RAY_PACKS_HOME")
    if override:
        return Path(override).expanduser()
    data = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(data) / "mantha-ray" / "packs"


def _read_state(home: Path) -> dict[str, Any]:
    path = home / "state.json"
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"current": None, "highest_signed": None, "history": []}
    except (OSError, ValueError) as exc:
        raise PackInstallError(f"the pack state file is unreadable ({path}): {exc}") from exc
    if not isinstance(state, dict) or not isinstance(state.get("history"), list):
        raise PackInstallError(f"the pack state file is invalid ({path})")
    return state


def _write_json_atomic(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name, dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=1)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _install_name(version: str, verified: bool) -> str:
    return version if verified else f"{version}-unsigned"


def current(home: Path | None = None) -> Installed | None:
    home = home or packs_home()
    state = _read_state(home)
    name = state.get("current")
    if not isinstance(name, str):
        return None
    entry = next((h for h in state["history"] if h.get("name") == name), None)
    directory = home / "installs" / name
    if (
        entry is None
        or directory.is_symlink()
        or not (directory / "bundle").is_dir()
        or "," in str(directory)
    ):
        return None
    return Installed(
        version=entry["version"],
        verified=entry.get("verified") is True,
        directory=directory,
        installed_at=entry.get("installed_at", ""),
        created_at=entry.get("created_at"),
    )


def current_install_dir(home: Path | None = None) -> Path | None:
    try:
        installed = current(home)
    except PackInstallError:
        return None
    return installed.directory if installed else None


def safe_extract(tarball: Path, destination: Path) -> None:
    # Plain files and folders only, nothing outside destination, bounded size.
    if tarball.stat().st_size > MAX_BUNDLE_BYTES:
        raise PackInstallError("the bundle is larger than allowed")
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    total = 0
    try:
        with tarfile.open(tarball, "r:gz") as archive:
            members = []
            for member in archive:
                members.append(member)
                if len(members) > MAX_MEMBERS:
                    raise PackInstallError("the bundle has too many files")
                if not (member.isfile() or member.isdir()):
                    raise PackInstallError(f"the bundle contains a link or special file: {member.name}")
                target = (destination / member.name).resolve()
                if target != root and root not in target.parents:
                    raise PackInstallError(f"a bundle path escapes the destination: {member.name}")
                total += member.size
                if total > MAX_UNPACKED_BYTES:
                    raise PackInstallError("the bundle unpacks to more than allowed")
            archive.extractall(destination, members=members, filter="data")
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise PackInstallError(f"the bundle can't be unpacked: {exc}") from exc


def _check_app_version(bundle: BundleInfo) -> None:
    if app_version_key(bundle.min_app_version) > app_version_key(__version__):
        raise PackInstallError(
            f"bundle {bundle.bundle_version} needs Mantha Ray {bundle.min_app_version} "
            f"or newer (this is {__version__}); update Mantha Ray first"
        )


def _validate(staging: Path, compile_check: CompileCheck | None) -> tuple[BundleInfo, dict[str, Any]]:
    try:
        bundle = validate_bundle(staging / "bundle")
    except ContractError as exc:
        raise PackInstallError(f"the bundle is invalid: {exc}") from exc
    _check_app_version(bundle)
    checked: dict[str, Any] = {}
    if compile_check is not None:
        checked = compile_check(staging)
    return bundle, checked


def _switch(
    home: Path,
    staging: Path,
    bundle: BundleInfo,
    *,
    verified: bool,
    sha256: str | None,
) -> Installed:
    state = _read_state(home)
    name = _install_name(bundle.bundle_version, verified)
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    _write_json_atomic(
        staging / "install.json",
        {"bundle_version": bundle.bundle_version, "verified": verified,
         "installed_at": now, "sha256": sha256},
    )
    installs = home / "installs"
    installs.mkdir(parents=True, exist_ok=True)
    final = installs / name
    if final.exists():
        # Reinstalling the same version (e.g. after a failed one): replace it.
        shutil.rmtree(final)
    os.replace(staging, final)

    history = [h for h in state["history"] if h.get("name") != name]
    history.append({
        "name": name, "version": bundle.bundle_version, "verified": verified,
        "installed_at": now, "created_at": bundle.created_at, "sha256": sha256,
    })
    state["history"] = history
    state["current"] = name
    if verified:
        highest = state.get("highest_signed")
        if not highest or bundle_version_key(bundle.bundle_version) > bundle_version_key(highest):
            state["highest_signed"] = bundle.bundle_version
    _write_json_atomic(home / "state.json", state)
    _prune(home, state)
    return Installed(bundle.bundle_version, verified, final, now, bundle.created_at)


def _prune(home: Path, state: dict[str, Any]) -> None:
    keep = {h["name"] for h in state["history"][-KEEP_INSTALLS:]} | {state.get("current")}
    state["history"] = [h for h in state["history"] if h["name"] in keep]
    _write_json_atomic(home / "state.json", state)
    for directory in (home / "installs").iterdir():
        if directory.name not in keep:
            shutil.rmtree(directory, ignore_errors=True)


def _staging(home: Path) -> Path:
    (home / "installs").mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=".staging-", dir=home / "installs"))


def install_signed(
    tarball: Path,
    *,
    signature: Path | None = None,
    public_key_text: str | None = None,
    compile_check: CompileCheck | None = None,
    home: Path | None = None,
) -> Installed:
    """Install a signed bundle, in the order the bundle contract sets out."""

    home = home or packs_home()
    signature = signature or tarball.with_name(tarball.name + ".minisig")
    if public_key_text is None:
        if not PUBLIC_KEY_PATH.is_file():
            raise PackInstallError(
                "no release public key is configured, so signed bundles can't be "
                f"checked; put the key from `hermit keygen` at {PUBLIC_KEY_PATH}"
            )
        public_key_text = PUBLIC_KEY_PATH.read_text(encoding="utf-8")
    if not signature.is_file():
        raise PackInstallError(f"no signature next to the bundle ({signature.name})")

    # 1-3: signature, exact trusted comment, archive hash.
    try:
        comment = verify_file(tarball, signature, public_key_text)
        version, signed_sha = parse_trusted_comment(comment)
    except SignatureError as exc:
        raise PackInstallError(f"signature check failed: {exc}") from exc
    try:
        bundle_version_key(version)
    except ContractError as exc:
        raise PackInstallError(f"the signed comment names a bad version {version!r}") from exc
    sha = sha256_file(tarball)
    if sha != signed_sha:
        raise PackInstallError("the archive's sha256 doesn't match the signed comment")

    # 4: no rollbacks from a download; the same version is nothing to do.
    state = _read_state(home)
    highest = state.get("highest_signed")
    if highest and bundle_version_key(version) < bundle_version_key(highest):
        raise PackInstallError(
            f"bundle {version} is older than {highest}, which was already installed "
            "(rollback refused; use `mantha-ray packs rollback` to go back on purpose)"
        )
    installed = current(home)
    if installed and installed.verified and installed.version == version:
        raise PackInstallError(f"bundle {version} is already installed")

    # 5-7: safe unpack, validation and compile check, app version.
    staging = _staging(home)
    try:
        safe_extract(tarball, staging / "bundle")
        bundle, _ = _validate(staging, compile_check)
        if bundle.bundle_version != version:
            raise PackInstallError(
                f"manifest says {bundle.bundle_version} but the signature is for {version}"
            )
        # 8: switch atomically and record the version.
        return _switch(home, staging, bundle, verified=True, sha256=sha)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def install_unsigned(
    folder: Path,
    *,
    compile_check: CompileCheck | None = None,
    home: Path | None = None,
) -> Installed:
    """Install an unsigned bundle folder (`hermit export-bundle --unsigned`), for testing."""

    home = home or packs_home()
    try:
        validate_bundle(folder)  # before copying anything
    except ContractError as exc:
        raise PackInstallError(f"the bundle is invalid: {exc}") from exc
    staging = _staging(home)
    try:
        shutil.copytree(folder, staging / "bundle", symlinks=True)
        bundle, _ = _validate(staging, compile_check)
        return _switch(home, staging, bundle, verified=False, sha256=None)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def rollback(home: Path | None = None) -> Installed:
    """Go back to the install before the current one. Local and explicit only."""

    home = home or packs_home()
    state = _read_state(home)
    names = [h["name"] for h in state["history"]]
    current_name = state.get("current")
    if current_name not in names or names.index(current_name) == 0:
        raise PackInstallError("there is no earlier install to go back to")
    previous = state["history"][names.index(current_name) - 1]
    if not (home / "installs" / previous["name"] / "bundle").is_dir():
        raise PackInstallError(f"the earlier install {previous['name']} is missing")
    state["current"] = previous["name"]
    # The rollback floor (highest_signed) stays, so downloads still can't go back.
    _write_json_atomic(home / "state.json", state)
    installed = current(home)
    assert installed is not None
    return installed


def status(home: Path | None = None) -> dict[str, Any]:
    home = home or packs_home()
    state = _read_state(home)
    installed = current(home)
    result: dict[str, Any] = {
        "home": str(home),
        "installed": None,
        "highest_signed": state.get("highest_signed"),
        "history": [
            {k: h.get(k) for k in ("version", "verified", "installed_at")}
            for h in state["history"]
        ],
        "public_key": PUBLIC_KEY_PATH.is_file(),
    }
    if installed is None:
        return result
    info: dict[str, Any] = {
        "version": installed.version,
        "verified": installed.verified,
        "installed_at": installed.installed_at,
        "created_at": installed.created_at,
        "stale": False,
    }
    try:
        bundle = validate_bundle(installed.directory / "bundle")
        info["packs"] = [
            {"id": p.id, "version": p.version, "kind": p.kind, "rules": len(p.rules),
             "loaded": p.loaded_here}
            for p in bundle.packs
        ]
    except ContractError as exc:
        info["error"] = str(exc)
    if installed.created_at:
        try:
            created = datetime.strptime(installed.created_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
            info["stale"] = (datetime.now(UTC) - created).days > STALE_AFTER_DAYS
        except ValueError:
            pass
    result["installed"] = info
    return result
