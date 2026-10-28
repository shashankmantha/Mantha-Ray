from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .contract import BUNDLE_VERSION_RE, ContractError, bundle_version_key
from .store import (
    MAX_BUNDLE_BYTES,
    CompileCheck,
    Installed,
    PackInstallError,
    _read_state,
    current,
    install_signed,
    packs_home,
)

# Hermit publishes signed bundles as GitHub releases here. Only the host
# downloads; scan containers never have network access. A download is only
# ever passed to install_signed, so the signature, the version, the rollback
# floor and every rule are checked exactly as for a manual install.
RELEASE_REPO = "shashankmantha/mantha-packs"
API_ROOT = "https://api.github.com"
# Hosts a release or its files may be served from (GitHub redirects asset
# downloads to its storage hosts).
ALLOWED_HOSTS = frozenset({
    "api.github.com",
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
})
MAX_RELEASE_JSON = 2 * 2**20
MAX_SIGNATURE_BYTES = 4096
TIMEOUT_SECONDS = 30
USER_AGENT = "Mantha-Ray-packs-update"

TARBALL_RE = re.compile(r"^mantha-packs-(\d{4}\.\d{1,2}\.\d{1,2}\.\d{1,4})\.tar\.gz$")

Opener = Callable[[urllib.request.Request, float], Any]


@dataclass(frozen=True, slots=True)
class Release:
    version: str
    tarball_url: str
    signature_url: str
    tarball_name: str
    page: str | None


def release_repo() -> str:
    # For testing a fork; the release key still has to match.
    repo = os.environ.get("MANTHA_RAY_PACKS_REPO", RELEASE_REPO)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}", repo):
        raise PackInstallError(f"bad release repository {repo!r}")
    return repo


class _NoInsecureRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _check_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        raise PackInstallError(f"refusing to download from {parts.scheme}://{parts.hostname}")


def _default_opener(request: urllib.request.Request, timeout: float):
    # Honours HTTPS_PROXY like other tools; redirects stay on GitHub over HTTPS.
    opener = urllib.request.build_opener(_NoInsecureRedirects())
    return opener.open(request, timeout=timeout)


def _fetch(url: str, limit: int, opener: Opener, accept: str = "*/*") -> bytes:
    _check_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    try:
        with opener(request, TIMEOUT_SECONDS) as response:
            final = response.geturl() if hasattr(response, "geturl") else url
            _check_url(final)
            data = response.read(limit + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise PackInstallError("no release found (has Hermit published one yet?)") from exc
        if exc.code == 403:
            raise PackInstallError("GitHub refused the request (rate limit?); try again later") from exc
        raise PackInstallError(f"download failed: HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise PackInstallError(f"couldn't reach GitHub: {reason}") from exc
    if len(data) > limit:
        raise PackInstallError("the download is larger than allowed")
    return data


def latest_release(*, opener: Opener = _default_opener) -> Release:
    repo = release_repo()
    raw = _fetch(
        f"{API_ROOT}/repos/{repo}/releases/latest", MAX_RELEASE_JSON, opener,
        accept="application/vnd.github+json",
    )
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        raise PackInstallError("GitHub's release information isn't valid JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("assets"), list):
        raise PackInstallError("GitHub's release information is missing its files")

    tarballs: dict[str, dict] = {}
    signatures: dict[str, dict] = {}
    for asset in payload["assets"]:
        if not isinstance(asset, dict):
            continue
        name, url = asset.get("name"), asset.get("browser_download_url")
        if not isinstance(name, str) or not isinstance(url, str):
            continue
        if TARBALL_RE.match(name):
            tarballs[name] = asset
        elif name.endswith(".tar.gz.minisig") and TARBALL_RE.match(name[: -len(".minisig")]):
            signatures[name[: -len(".minisig")]] = asset
    pairs = [name for name in tarballs if name in signatures]
    if len(pairs) != 1:
        raise PackInstallError(
            "the latest release should hold exactly one mantha-packs-<version>.tar.gz "
            f"with its .minisig (found {len(pairs)})"
        )
    name = pairs[0]
    version = TARBALL_RE.match(name).group(1)  # type: ignore[union-attr]
    tag = payload.get("tag_name")
    if isinstance(tag, str) and tag.lstrip("v") != version:
        raise PackInstallError(f"release {tag} holds a bundle for {version}")
    size = tarballs[name].get("size")
    if isinstance(size, int) and size > MAX_BUNDLE_BYTES:
        raise PackInstallError("the bundle is larger than allowed")
    page = payload.get("html_url")
    return Release(
        version=version,
        tarball_url=tarballs[name]["browser_download_url"],
        signature_url=signatures[name]["browser_download_url"],
        tarball_name=name,
        page=page if isinstance(page, str) else None,
    )


@dataclass(frozen=True, slots=True)
class UpdateCheck:
    latest: str
    installed: str | None
    installed_verified: bool
    update_available: bool
    older_than_installed: bool
    page: str | None


def check(*, home: Path | None = None, opener: Opener = _default_opener) -> tuple[UpdateCheck, Release]:
    home = home or packs_home()
    release = latest_release(opener=opener)
    installed = current(home)
    floor = _read_state(home).get("highest_signed")
    try:
        latest_key = bundle_version_key(release.version)
        older = bool(floor) and latest_key < bundle_version_key(floor)
        newer = installed is None or not installed.verified or (
            latest_key > bundle_version_key(installed.version)
        )
    except ContractError as exc:
        raise PackInstallError(str(exc)) from exc
    return (
        UpdateCheck(
            latest=release.version,
            installed=installed.version if installed else None,
            installed_verified=bool(installed and installed.verified),
            update_available=newer and not older,
            older_than_installed=older,
            page=release.page,
        ),
        release,
    )


def update(
    *,
    compile_check: CompileCheck | None = None,
    home: Path | None = None,
    opener: Opener = _default_opener,
    public_key_text: str | None = None,
) -> tuple[UpdateCheck, Installed | None]:
    """Install the latest signed release if it's newer than what's installed."""

    home = home or packs_home()
    status, release = check(home=home, opener=opener)
    if status.older_than_installed:
        raise PackInstallError(
            f"the latest release ({release.version}) is older than a bundle already "
            "installed; refusing it (a rolled-back or tampered release?)"
        )
    if not status.update_available:
        return status, None
    if not BUNDLE_VERSION_RE.match(release.version):
        raise PackInstallError(f"bad release version {release.version!r}")

    (home / "downloads").mkdir(parents=True, exist_ok=True)
    folder = Path(tempfile.mkdtemp(prefix="update-", dir=home / "downloads"))
    try:
        tarball = folder / release.tarball_name
        signature = folder / f"{release.tarball_name}.minisig"
        signature.write_bytes(_fetch(release.signature_url, MAX_SIGNATURE_BYTES, opener))
        tarball.write_bytes(_fetch(release.tarball_url, MAX_BUNDLE_BYTES, opener))
        installed = install_signed(
            tarball,
            signature=signature,
            public_key_text=public_key_text,
            compile_check=compile_check,
            home=home,
        )
        if installed.version != release.version:
            raise PackInstallError("the installed bundle isn't the release that was downloaded")
        return status, installed
    finally:
        shutil.rmtree(folder, ignore_errors=True)
