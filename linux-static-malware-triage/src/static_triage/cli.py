"""Command-line interface for the static triage scanner."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .config import ScanConfig, ScanLimits
from .errors import TriageError
from .scanner import run_inventory_scan


def build_parser() -> argparse.ArgumentParser:
    """Construct the command-line argument parser."""

    parser = argparse.ArgumentParser(
        prog="static-triage",
        description=(
            "Inventory and hash an extracted staging "
            "directory without executing samples."
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
        help="run the current scanner milestone",
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

    gui = subparsers.add_parser(
        "gui",
        help="launch the desktop scanner interface",
    )

    gui.add_argument(
        "--container-engine",
        default="docker",
        help="container engine command (default: docker)",
    )

    gui.add_argument(
        "--image",
        default="static-triage:core",
        help="analysis worker image (default: static-triage:core)",
    )

    return parser


def _run_gui(args: argparse.Namespace) -> int:
    """Import and launch Tkinter only for the GUI subcommand."""

    try:
        from .gui import launch_gui
    except ModuleNotFoundError as exc:
        if exc.name != "tkinter":
            raise

        print(
            json.dumps(
                {
                    "ok": False,
                    "error": (
                        "Tkinter is required to launch the GUI."
                    ),
                }
            ),
            file=sys.stderr,
        )
        return 2

    try:
        return launch_gui(
            engine=args.container_engine,
            image=args.image,
        )
    except RuntimeError as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": str(exc),
                }
            ),
            file=sys.stderr,
        )
        return 2


def main(argv: list[str] | None = None) -> int:
    """Run the command-line interface."""

    args = build_parser().parse_args(argv)

    if args.command == "gui":
        return _run_gui(args)

    if args.command != "scan":
        return 2

    limits = ScanLimits(
        max_file_count=args.max_files,
        max_total_bytes=args.max_total_gib * 1024**3,
        max_file_bytes=args.max_file_gib * 1024**3,
        max_depth=args.max_depth,
    )

    config = ScanConfig(
        staging_root=args.staging_root,
        results_root=args.results_root,
        limits=limits,
    )

    try:
        result = run_inventory_scan(
            args.staging_subdirectory,
            config,
        )

    except (TriageError, ValueError, OSError) as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": str(exc),
                }
            ),
            file=sys.stderr,
        )

        return 2

    print(
        json.dumps(
            {
                "ok": True,
                "case_id": result.case_id,
                "status": result.status,
                "case_directory": str(
                    result.case_directory
                ),
                "report_path": str(result.report_path),
            },
            sort_keys=True,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
