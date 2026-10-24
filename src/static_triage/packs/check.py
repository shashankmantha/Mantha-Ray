from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .store import PackInstallError

CHECK_TIMEOUT_SECONDS = 600


def container_compile_check(
    install_dir: Path,
    *,
    image: str = "static-triage:core",
    engine: str = "docker",
    target: str = "/packs",
) -> dict[str, Any]:
    """Compile a staged bundle with the scan image's YARA-X, without network.

    Rule text is untrusted until it compiles, so it is compiled in the same
    hardened container the scans use, by the same YARA-X version.
    """

    engine_path = shutil.which(engine)
    if engine_path is None:
        raise PackInstallError(
            f"'{engine}' was not found, so the rules can't be checked; "
            "install it and run ./scripts/setup.sh"
        )
    if "," in str(install_dir):
        raise PackInstallError("the pack folder path can't contain commas")
    command = [
        engine_path, "run", "--rm",
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--security-opt", "label=disable",
        "--pids-limit", "64",
        "--memory", "2g",
        "--cpus", "1",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777",
        "--mount", f"type=bind,source={install_dir},target={target},readonly",
        image,
        "packs-check",
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=CHECK_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PackInstallError("checking the rules took too long") from exc
    except OSError as exc:
        raise PackInstallError(f"the rule check couldn't start: {exc}") from exc

    last = (completed.stdout.strip().splitlines() or [""])[-1]
    try:
        result = json.loads(last)
    except ValueError:
        result = None
    if not isinstance(result, dict):
        detail = (completed.stderr.strip().splitlines() or ["no output"])[-1][:300]
        if "Unknown" in detail or "invalid choice" in detail:
            detail = "the scan image is too old to check rule packs; run ./scripts/setup.sh"
        raise PackInstallError(f"the rule check failed: {detail}")
    if result.get("ok") is not True:
        detail = str(result.get("error")).removeprefix("no rule pack compiles: ")
        raise PackInstallError(f"the rules don't compile: {detail[:400]}")
    return result
