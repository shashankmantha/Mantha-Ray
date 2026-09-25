"""Command-line interface for Mantha Ray."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .config import ScanConfig, ScanLimits
from .errors import TriageError
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
        default=25_000,
    )

    scan.add_argument(
        "--max-total-gib",
        type=int,
        default=100,
    )

    scan.add_argument(
        "--max-file-gib",
        type=int,
        default=4,
    )

    scan.add_argument(
        "--max-depth",
        type=int,
        default=32,
    )

    # Internal host/container protocol switch. Normal CLI callers still
    # receive only the final JSON result unless this flag is supplied.
    scan.add_argument(
        "--progress-jsonl",
        action="store_true",
        help=argparse.SUPPRESS,
    )

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

    if args.command != "scan":
        return 2

    limits = ScanLimits(
        max_file_count=args.max_files,
        max_total_bytes=(
            args.max_total_gib * 1024**3
        ),
        max_file_bytes=(
            args.max_file_gib * 1024**3
        ),
        max_depth=args.max_depth,
    )

    config = ScanConfig(
        staging_root=args.staging_root,
        results_root=args.results_root,
        limits=limits,
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