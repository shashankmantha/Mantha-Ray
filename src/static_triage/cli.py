from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import stop_request
from . import __version__
from .config import ScanConfig
from .errors import TriageError
from .resource_profiles import (
    ResourceProfile,
    ResourceProfileError,
    profile_from_dict,
    resolve_profile,
)
from .scanner import run_inventory_scan


def build_parser(
    prog: str = "static-triage",
) -> argparse.ArgumentParser:
    """Construct the command-line argument parser."""

    parser = argparse.ArgumentParser(
        prog=prog,
        description=(
            "Inventory and analyze files without "
            "executing samples."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    scan = subparsers.add_parser(
        "scan",
        help="run the container scanner",
    )

    scan.add_argument(
        "staging_subdirectory",
        help=(
            "relative directory identifier beneath "
            "--staging-root"
        ),
    )

    scan.add_argument(
        "--staging-root",
        type=Path,
        required=True,
    )

    scan.add_argument(
        "--results-root",
        type=Path,
        required=True,
    )

    scan.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="overrides the resource profile (default 25000)",
    )

    scan.add_argument(
        "--max-total-gib",
        type=int,
        default=None,
        help="overrides the resource profile (default 100)",
    )

    scan.add_argument(
        "--max-file-gib",
        type=int,
        default=None,
        help="overrides the resource profile (default 4)",
    )

    scan.add_argument(
        "--max-depth",
        type=int,
        default=None,
        help="overrides the resource profile (default 32)",
    )

    scan.add_argument(
        "--resource-profile",
        metavar="JSON",
        default=None,
        help=(
            "resource profile from the host, as JSON; "
            "validated before use (default: balanced)"
        ),
    )

    # Internal host/container protocol switch. Normal CLI callers still
    # receive only the final JSON result unless this flag is supplied.
    scan.add_argument(
        "--progress-jsonl",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    packs = subparsers.add_parser(
        "packs",
        help="install and inspect YARA rule packs from Mantha Hermit",
    )
    packs_actions = packs.add_subparsers(dest="packs_command", required=True)
    install = packs_actions.add_parser(
        "install",
        help="install a signed bundle (.tar.gz with its .minisig next to it)",
    )
    install.add_argument("bundle", type=Path)
    install.add_argument(
        "--unsigned",
        action="store_true",
        help="install an unsigned bundle folder, for testing only",
    )
    install.add_argument("--image", default="static-triage:core")
    install.add_argument("--container-engine", default="docker")
    packs_actions.add_parser("status", help="show the installed bundle and your own rules")
    add = packs_actions.add_parser(
        "add",
        help="add your own .yar rule file; it runs in every scan",
    )
    add.add_argument("rule_file", type=Path)
    add.add_argument("--name", default=None, help="name for these rules (default: from the file name)")
    add.add_argument(
        "--severity",
        choices=("info", "suspicious", "threat"),
        default="suspicious",
        help="what a match means: suspicious (default) raises the case to Needs Review, "
        "threat to High Concern, info only lists it",
    )
    add.add_argument("--replace", action="store_true", help="replace rules with the same name")
    add.add_argument("--image", default="static-triage:core")
    add.add_argument("--container-engine", default="docker")
    remove = packs_actions.add_parser("remove", help="remove your own rules by name")
    remove.add_argument("name")
    packs_actions.add_parser(
        "rollback",
        help="go back to the previously installed bundle",
    )

    # Runs inside the scan image: compiles the bundle mounted at /packs.
    subparsers.add_parser("packs-check", help=argparse.SUPPRESS)

    gui = subparsers.add_parser(
        "gui",
        help="launch the Tkinter interface",
    )

    gui.add_argument(
        "--container-engine",
        default="docker",
        help=(
            "container engine command "
            "(default: docker)"
        ),
    )

    gui.add_argument(
        "--image",
        default="static-triage:core",
        help=(
            "analysis worker image "
            "(default: static-triage:core)"
        ),
    )

    web = subparsers.add_parser(
        "web",
        help="launch the local Mantha Ray web interface",
    )

    web.add_argument(
        "--container-engine",
        default="docker",
        help=(
            "container engine command "
            "(default: docker)"
        ),
    )

    web.add_argument(
        "--image",
        default="static-triage:core",
        help=(
            "analysis worker image "
            "(default: static-triage:core)"
        ),
    )

    web.add_argument(
        "--port",
        type=int,
        default=0,
        help=(
            "loopback port; zero chooses a "
            "random available port"
        ),
    )

    web.add_argument(
        "--no-browser",
        action="store_true",
        help=(
            "print the authenticated URL instead "
            "of opening it"
        ),
    )

    return parser


def _print_error(
    message: str,
) -> int:
    """Print a bounded CLI error response."""

    print(
        json.dumps(
            {
                "ok": False,
                "error": message,
            }
        ),
        file=sys.stderr,
        flush=True,
    )

    return 2


MAX_RESOURCE_PROFILE_CHARS = 16_384

_INVENTORY_FLAGS = {
    "max_files": "max_file_count",
    "max_total_gib": "max_total_gib",
    "max_file_gib": "max_file_gib",
    "max_depth": "max_depth",
}


def resolve_scan_profile(
    args: argparse.Namespace,
) -> ResourceProfile:
    """Resolve the profile for an in-container scan.

    The host's profile is revalidated rather than trusted. Explicit
    inventory flags override it, which makes the profile custom.
    """

    raw = args.resource_profile
    if raw is None:
        profile = resolve_profile()
    else:
        if len(raw) > MAX_RESOURCE_PROFILE_CHARS:
            raise ResourceProfileError([(
                None,
                "The resource profile is too large.",
            )])
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ResourceProfileError([(
                None,
                "The resource profile is not valid JSON.",
            )]) from exc
        profile = profile_from_dict(data)

    explicit = {
        field: getattr(args, flag)
        for flag, field in _INVENTORY_FLAGS.items()
        if getattr(args, flag) is not None
    }
    if not explicit:
        return profile

    return resolve_profile(
        profile.base,
        {**profile.changed_fields(), **explicit},
    )


def _print_progress(
    stage: str,
    status: str,
    message: str,
) -> None:
    """Write one flushed JSONL stage event to stdout."""

    print(
        json.dumps(
            {
                "type": "progress",
                "stage": stage,
                "status": status,
                "message": message,
            },
            sort_keys=True,
        ),
        flush=True,
    )


# A queue line must stay under the host's 8192-character progress limit.
QUEUE_LINE_BUDGET = 6000


def _print_queue(
    stage: str,
    items: list[dict[str, object]],
) -> None:
    """Write a stage's planned file order as one or more JSONL lines."""

    total = len(items)
    chunk: list[dict[str, object]] = []
    offset = 0

    def flush() -> None:
        print(
            json.dumps(
                {
                    "type": "queue",
                    "stage": stage,
                    "offset": offset,
                    "total": total,
                    "items": chunk,
                },
                sort_keys=True,
            ),
            flush=True,
        )

    size = 0
    for item in items:
        item_size = len(json.dumps(item)) + 2
        if chunk and size + item_size > QUEUE_LINE_BUDGET:
            flush()
            offset += len(chunk)
            chunk = []
            size = 0
        chunk.append(item)
        size += item_size
    if chunk:
        flush()


def _run_gui(
    args: argparse.Namespace,
) -> int:
    """Import Tkinter only for the GUI subcommand."""

    try:
        from .gui import launch_gui

    except ModuleNotFoundError as exc:
        if exc.name != "tkinter":
            raise

        return _print_error(
            "Tkinter is required to launch the GUI."
        )

    try:
        return launch_gui(
            engine=args.container_engine,
            image=args.image,
        )

    except RuntimeError as exc:
        return _print_error(str(exc))


def _run_web(
    args: argparse.Namespace,
) -> int:
    """Launch the local browser application."""

    from .web_launcher import launch_web

    try:
        return launch_web(
            engine=args.container_engine,
            image=args.image,
            port=args.port,
            open_browser=not args.no_browser,
        )

    except RuntimeError as exc:
        return _print_error(str(exc))


def main(
    argv: list[str] | None = None,
    *,
    prog: str = "static-triage",
) -> int:
    """Run the command-line interface."""

    args = build_parser(
        prog=prog
    ).parse_args(argv)

    if args.command == "gui":
        return _run_gui(args)

    if args.command == "web":
        return _run_web(args)

    if args.command == "packs":
        from .packs.commands import run_packs_command

        return run_packs_command(args)

    if args.command == "packs-check":
        from .packs.commands import run_packs_check

        return run_packs_check()

    if args.command != "scan":
        return 2

    # Installed first, so a stop request that arrives early is not lost
    # and doesn't kill the process (SIGUSR1's default action).
    try:
        stop_request.install()
    except ValueError:
        pass  # not the main thread (embedded use); stop is unavailable

    try:
        profile = resolve_scan_profile(args)
    except ResourceProfileError as exc:
        return _print_error(
            f"Invalid resource profile: {exc}"
        )

    limits = profile.scan_limits()

    config = ScanConfig(
        staging_root=args.staging_root,
        results_root=args.results_root,
        limits=limits,
        resource_profile={
            **profile.to_dict(),
            "changed": profile.changed_fields(),
            "effective_workers": profile.effective_workers,
        },
    )

    progress_callback = (
        _print_progress
        if args.progress_jsonl
        else None
    )

    try:
        result = run_inventory_scan(
            args.staging_subdirectory,
            config,
            on_progress=progress_callback,
            on_queue=_print_queue if args.progress_jsonl else None,
        )

    except (
        TriageError,
        ValueError,
        OSError,
    ) as exc:
        return _print_error(str(exc))

    print(
        json.dumps(
            {
                "ok": True,
                "case_id": result.case_id,
                "status": result.status,
                "case_directory": str(
                    result.case_directory
                ),
                "report_path": str(
                    result.report_path
                ),
            },
            sort_keys=True,
        ),
        flush=True,
    )

    return 0


def branded_main(
    argv: list[str] | None = None,
) -> int:
    """Run Mantha Ray, opening the web app by default."""

    arguments = list(
        sys.argv[1:]
        if argv is None
        else argv
    )

    if not arguments:
        arguments = ["web"]

    return main(
        arguments,
        prog="mantha-ray",
    )


if __name__ == "__main__":
    raise SystemExit(main())