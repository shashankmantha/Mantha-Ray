from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from pathlib import Path

from .. import __version__
from . import local, store, update
from .check import container_compile_check


def _print_installed(installed: store.Installed) -> None:
    kind = "signed" if installed.verified else "UNSIGNED (testing only)"
    print(f"Installed bundle {installed.version} ({kind}).")
    print(f"  {installed.directory}")


def _update_line(status: update.UpdateCheck) -> str:
    if status.older_than_installed:
        return (f"The latest release ({status.latest}) is older than a bundle already "
                "installed, so it won't be used.")
    if status.update_available:
        return f"A newer bundle is available: {status.latest} (installed: {status.installed or 'none'})."
    return f"Up to date: {status.latest}."


def run_packs_command(args: argparse.Namespace) -> int:
    try:
        if args.packs_command == "install":
            def check(staging: Path) -> dict:
                print("Checking that every rule compiles (in the scan container)...")
                return container_compile_check(
                    staging, image=args.image, engine=args.container_engine,
                )

            if args.unsigned:
                print("Warning: unsigned bundles aren't checked for tampering. Use them for testing only.")
                installed = store.install_unsigned(args.bundle, compile_check=check)
            else:
                installed = store.install_signed(args.bundle, compile_check=check)
            _print_installed(installed)
            return 0

        if args.packs_command == "update":
            print(f"Checking {update.release_repo()} for a newer signed bundle...")
            if args.check:
                status, _ = update.check()
                print(_update_line(status))
                return 0

            def check_update(staging: Path) -> dict:
                print("Checking that every rule compiles (in the scan container)...")
                return container_compile_check(
                    staging, image=args.image, engine=args.container_engine,
                )

            status, installed = update.update(compile_check=check_update)
            if installed is None:
                print(_update_line(status))
            else:
                print(f"Updated from {status.installed or 'nothing'} to {installed.version}.")
                _print_installed(installed)
            return 0

        if args.packs_command == "add":
            path: Path = args.rule_file
            if not path.is_file():
                print(f"Error: {path} is not a file.")
                return 1
            if path.stat().st_size > local.MAX_RULE_FILE:
                print("Error: the rule file is larger than 8 MiB.")
                return 1
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                print("Error: the rule file isn't UTF-8 text.")
                return 1

            def check_local(staging: Path) -> dict:
                print("Checking that the rules compile (in the scan container)...")
                return container_compile_check(
                    staging, image=args.image, engine=args.container_engine,
                    target="/packs-local",
                )

            added = local.add_local(
                text, source=path.name, name=args.name, severity=args.severity,
                replace=args.replace, compile_check=check_local,
            )
            print(
                f"Added {added['rules']} rule{'s' if added['rules'] != 1 else ''} "
                f"as local:{added['name']} (severity {added['severity']})."
            )
            print("They run in every scan from now on, beside the signed packs.")
            return 0

        if args.packs_command == "remove":
            local.remove_local(args.name)
            print(f"Removed local:{args.name}.")
            return 0

        if args.packs_command == "rollback":
            installed = store.rollback()
            print("Rolled back.")
            _print_installed(installed)
            return 0

        info = store.status()
        installed = info["installed"]
        if installed is None:
            print("No rule packs are installed.")
            print("Install a bundle from Mantha Hermit: mantha-ray packs install <bundle>.tar.gz")
        else:
            kind = "signed" if installed["verified"] else "UNSIGNED (testing only)"
            print(f"Bundle {installed['version']} ({kind}), built {installed['created_at']}, "
                  f"installed {installed['installed_at']}")
            if installed.get("stale"):
                print(f"  Warning: this bundle is more than {store.STALE_AFTER_DAYS} days old.")
            for pack in installed.get("packs", []):
                used = "" if pack["loaded"] else " (not used by this edition)"
                print(f"  {pack['id']} v{pack['version']} ({pack['kind']}): {pack['rules']} rules{used}")
            if installed.get("error"):
                print(f"  Problem: {installed['error']}")
        if info["highest_signed"]:
            print(f"Newest signed bundle installed so far: {info['highest_signed']}")
        mine = local.list_local()
        if mine:
            print("Your own rules (local packs):")
            for pack in mine:
                if "error" in pack:
                    print(f"  local:{pack['name']}: not usable ({pack['error']})")
                else:
                    print(f"  local:{pack['name']}: {pack['rules']} rules, severity {pack['severity']}")
        if not info["public_key"]:
            print(f"No release public key at {store.PUBLIC_KEY_PATH}; only unsigned installs work.")
        return 0
    except store.PackInstallError as exc:
        print(f"Error: {exc}")
        return 1


def run_packs_check() -> int:
    from ..yara_scan import (
        LOCAL_PACKS_MOUNT,
        PACKS_MOUNT,
        RulesError,
        RulesUnavailable,
        compile_rules,
    )

    executable = shutil.which("yr")
    if executable is None:
        print(json.dumps({"ok": False, "error": "yr is not installed in this image"}))
        return 1
    work = Path(tempfile.mkdtemp(prefix="mantha-packs-check-"))
    try:
        rules, _ = compile_rules(
            PACKS_MOUNT, work, executable=executable, app_version=__version__,
            local_root=LOCAL_PACKS_MOUNT,
        )
    except (RulesError, RulesUnavailable) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1
    finally:
        shutil.rmtree(work, ignore_errors=True)
    # Every pack must compile on its own; leaving one out is fine for a scan
    # but not for an install.
    bad = [
        s for s in rules.skipped
        if "compile" in s["reason"] or s["reason"].startswith("invalid")
    ]
    if bad:
        print(json.dumps({"ok": False, "error": f"{bad[0]['id']}: {bad[0]['reason']}"}))
        return 1
    print(json.dumps({
        "ok": True,
        "bundle_version": rules.bundle.bundle_version if rules.bundle else None,
        "rules": sum(len(p.rules) for p in rules.packs),
        "packs": [p.id for p in rules.packs],
    }))
    return 0
