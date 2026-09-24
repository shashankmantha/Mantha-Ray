"""Native Linux desktop helpers for the local web interface."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .host_scan import HostScanError


def choose_directory(
    purpose: str,
    current_path: str | None = None,
) -> str | None:
    """Open a KDE or GTK directory chooser."""

    if purpose not in {
        "source",
        "results",
    }:
        raise HostScanError(
            "The directory picker purpose is invalid."
        )

    initial = Path(
        current_path or Path.home()
    ).expanduser()

    if not initial.is_dir():
        initial = Path.home()

    try:
        initial = initial.resolve(strict=True)
    except OSError as exc:
        raise HostScanError(
            "The initial directory is unavailable."
        ) from exc

    if purpose == "source":
        title = (
            "Mantha Ray — Choose a folder to scan"
        )
    else:
        title = (
            "Mantha Ray — Choose a results folder"
        )

    kdialog = shutil.which("kdialog")
    zenity = shutil.which("zenity")

    if kdialog is not None:
        command = [
            kdialog,
            "--getexistingdirectory",
            str(initial),
            "--title",
            title,
        ]

    elif zenity is not None:
        command = [
            zenity,
            "--file-selection",
            "--directory",
            f"--title={title}",
            f"--filename={initial}/",
        ]

    else:
        raise HostScanError(
            "No supported native folder picker was found. "
            "Install kdialog or zenity."
        )

    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=5 * 60,
        )

    except (
        OSError,
        subprocess.TimeoutExpired,
    ) as exc:
        raise HostScanError(
            "The native folder picker did not complete."
        ) from exc

    # Both kdialog and zenity use exit code 1 when
    # the user closes or cancels the dialog.
    if result.returncode == 1:
        return None

    if result.returncode != 0:
        raise HostScanError(
            "The native folder picker failed."
        )

    selected = result.stdout.strip()

    if not selected:
        return None

    try:
        path = Path(
            selected
        ).expanduser().resolve(strict=True)

    except OSError as exc:
        raise HostScanError(
            "The selected directory is unavailable."
        ) from exc

    if not path.is_dir():
        raise HostScanError(
            "The selected path is not a directory."
        )

    return str(path)


def open_directory(
    path: Path,
) -> None:
    """Open a validated directory in the file manager."""

    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise HostScanError(
            "The requested case directory is unavailable."
        ) from exc

    if not resolved.is_dir():
        raise HostScanError(
            "The requested case directory is unavailable."
        )

    opener = (
        shutil.which("xdg-open")
        or shutil.which("gio")
    )

    if opener is None:
        raise HostScanError(
            "No desktop folder opener was found."
        )

    command = [
        opener,
        str(resolved),
    ]

    if Path(opener).name == "gio":
        command.insert(
            1,
            "open",
        )

    try:
        subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    except OSError as exc:
        raise HostScanError(
            "The case directory could not be opened."
        ) from exc