"""Path-boundary checks for controlled scanner input and output."""

from __future__ import annotations

from pathlib import Path

from .errors import BoundaryError


def _is_within(path: Path, root: Path) -> bool:
    """Return whether path is equal to or contained by root."""

    return path == root or root in path.parents


def resolve_scan_target(
    staging_root: Path,
    staging_subdirectory: str,
) -> tuple[Path, Path]:
    """Resolve a directory identifier beneath the trusted staging root."""

    root = staging_root.expanduser().resolve(strict=True)

    if not root.is_dir():
        raise BoundaryError(
            f"staging root is not a directory: {root}"
        )

    requested = Path(staging_subdirectory)

    if requested.is_absolute():
        raise BoundaryError(
            "scan target must be a staging-relative directory identifier"
        )

    try:
        target = (root / requested).resolve(strict=True)
    except (FileNotFoundError, RuntimeError) as exc:
        raise BoundaryError(
            "scan target does not exist or contains a symlink loop"
        ) from exc

    if not _is_within(target, root):
        raise BoundaryError(
            "scan target resolves outside the configured staging root"
        )

    if not target.is_dir():
        raise BoundaryError("scan target must be a directory")

    return root, target


def resolve_results_root(
    results_root: Path,
    staging_root: Path,
    target: Path,
) -> Path:
    """Ensure results cannot be written inside the sample boundary."""

    output = results_root.expanduser().resolve(strict=False)

    if _is_within(output, staging_root) or _is_within(
        staging_root, output
    ):
        raise BoundaryError(
            "results root and staging root must not overlap"
        )

    if _is_within(output, target) or _is_within(target, output):
        raise BoundaryError(
            "results root and scan target must not overlap"
        )

    return output