
from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .config import ScanLimits

SCHEMA_VERSION = 1

CUSTOM = "custom"

# Time reserved for inventory, ClamAV, and report generation on top of
# the capa and FLOSS budgets when checking the host wall-clock limit.
HOST_TIMEOUT_MARGIN_SECONDS = 30 * 60

# Warn when a profile requests more than this share of Docker's memory.
MEMORY_WARNING_FRACTION = 0.75

_GIB = 1024**3
_MIB = 1024**2


@dataclass(frozen=True, slots=True)
class _FieldSpec:
    kind: str  # "int" or "cpus"
    minimum: float
    maximum: float
    label: str


# Canonical units: CPUs, MiB, seconds, and GiB for inventory sizes.
FIELDS: dict[str, _FieldSpec] = {
    # Container envelope, enforced by Docker.
    "cpus": _FieldSpec("cpus", 0.5, 64, "CPUs"),
    "memory_mib": _FieldSpec("int", 1024, 262_144, "Memory (MiB)"),
    "pids_limit": _FieldSpec("int", 64, 4096, "Process limit"),
    "tmp_mib": _FieldSpec("int", 64, 65_536, "Temporary space (MiB)"),
    "host_timeout_seconds": _FieldSpec(
        "int", 600, 172_800, "Host time limit (seconds)"
    ),
    # capa budgets, enforced inside the container.
    "max_capa_files": _FieldSpec("int", 1, 10_000, "capa file cap"),
    "capa_file_timeout_seconds": _FieldSpec(
        "int", 10, 7_200, "capa per-file timeout (seconds)"
    ),
    "capa_total_timeout_seconds": _FieldSpec(
        "int", 60, 86_400, "capa total budget (seconds)"
    ),
    # FLOSS budgets, enforced inside the container.
    "max_floss_files": _FieldSpec("int", 1, 10_000, "FLOSS file cap"),
    "floss_file_timeout_seconds": _FieldSpec(
        "int", 10, 7_200, "FLOSS per-file timeout (seconds)"
    ),
    "floss_total_timeout_seconds": _FieldSpec(
        "int", 60, 86_400, "FLOSS total budget (seconds)"
    ),
    # Inventory limits, enforced inside the container.
    "max_file_count": _FieldSpec("int", 1, 1_000_000, "Maximum files"),
    "max_total_gib": _FieldSpec("int", 1, 4096, "Maximum total size (GiB)"),
    "max_file_gib": _FieldSpec("int", 1, 64, "Maximum file size (GiB)"),
    "max_depth": _FieldSpec("int", 1, 256, "Maximum folder depth"),
}

_INVENTORY_DEFAULTS = {
    "max_file_count": 25_000,
    "max_total_gib": 100,
    "max_file_gib": 4,
    "max_depth": 32,
}

PRESETS: dict[str, dict[str, Any]] = {
    "constrained": {
        "cpus": 1,
        "memory_mib": 2048,
        "pids_limit": 128,
        "tmp_mib": 256,
        "host_timeout_seconds": 2 * 60 * 60,
        "max_capa_files": 250,
        "capa_file_timeout_seconds": 300,
        "capa_total_timeout_seconds": 30 * 60,
        "max_floss_files": 25,
        "floss_file_timeout_seconds": 600,
        "floss_total_timeout_seconds": 30 * 60,
        **_INVENTORY_DEFAULTS,
    },
    # Balanced reproduces the values used before profiles existed.
    "balanced": {
        "cpus": 2,
        "memory_mib": 4096,
        "pids_limit": 256,
        "tmp_mib": 512,
        "host_timeout_seconds": 4 * 60 * 60,
        "max_capa_files": 250,
        "capa_file_timeout_seconds": 300,
        "capa_total_timeout_seconds": 60 * 60,
        "max_floss_files": 50,
        "floss_file_timeout_seconds": 600,
        "floss_total_timeout_seconds": 60 * 60,
        **_INVENTORY_DEFAULTS,
    },
    "high": {
        "cpus": 4,
        "memory_mib": 8192,
        "pids_limit": 512,
        "tmp_mib": 1024,
        "host_timeout_seconds": 6 * 60 * 60,
        "max_capa_files": 250,
        "capa_file_timeout_seconds": 300,
        "capa_total_timeout_seconds": 2 * 60 * 60,
        "max_floss_files": 100,
        "floss_file_timeout_seconds": 600,
        "floss_total_timeout_seconds": 2 * 60 * 60,
        **_INVENTORY_DEFAULTS,
    },
}

DEFAULT_PRESET = "balanced"


class ResourceProfileError(ValueError):
    """A profile was rejected. ``problems`` maps fields to messages."""

    def __init__(
        self,
        problems: list[tuple[str | None, str]],
    ) -> None:
        self.problems = tuple(problems)
        super().__init__(
            "; ".join(message for _, message in self.problems)
        )


@dataclass(frozen=True, slots=True)
class ResourceProfile:
    """A fully resolved, validated resource profile."""

    name: str
    base: str
    cpus: float
    memory_mib: int
    pids_limit: int
    tmp_mib: int
    host_timeout_seconds: int
    max_capa_files: int
    capa_file_timeout_seconds: int
    capa_total_timeout_seconds: int
    max_floss_files: int
    floss_file_timeout_seconds: int
    floss_total_timeout_seconds: int
    max_file_count: int
    max_total_gib: int
    max_file_gib: int
    max_depth: int

    @property
    def is_custom(self) -> bool:
        return self.name == CUSTOM

    def values(self) -> dict[str, Any]:
        """Return every profile field in canonical units."""

        return {name: getattr(self, name) for name in FIELDS}

    def changed_fields(self) -> dict[str, Any]:
        """Return fields whose value differs from the base preset."""

        base = PRESETS[self.base]
        return {
            name: value
            for name, value in self.values().items()
            if value != base[name]
        }

    def scan_limits(self) -> ScanLimits:
        """Build the in-container limits. Unlisted limits keep defaults."""

        return ScanLimits(
            max_file_count=self.max_file_count,
            max_total_bytes=self.max_total_gib * _GIB,
            max_file_bytes=self.max_file_gib * _GIB,
            max_depth=self.max_depth,
            max_capa_files=self.max_capa_files,
            capa_file_timeout_seconds=float(
                self.capa_file_timeout_seconds
            ),
            capa_total_timeout_seconds=float(
                self.capa_total_timeout_seconds
            ),
            max_floss_files=self.max_floss_files,
            floss_file_timeout_seconds=float(
                self.floss_file_timeout_seconds
            ),
            floss_total_timeout_seconds=float(
                self.floss_total_timeout_seconds
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize for transport to the container and for reports."""

        return {
            "schema_version": SCHEMA_VERSION,
            "name": self.name,
            "base": self.base,
            "values": self.values(),
        }


def _check_value(
    name: str,
    value: object,
) -> tuple[float | int | None, str | None]:
    spec = FIELDS[name]
    # bool is a subclass of int; never accept it as a number.
    if isinstance(value, bool):
        return None, f"{spec.label} must be a number."
    if spec.kind == "int":
        if not isinstance(value, int):
            return None, f"{spec.label} must be a whole number."
        number: float | int = value
    else:
        if not isinstance(value, (int, float)) or not math.isfinite(
            value
        ):
            return None, f"{spec.label} must be a number."
        if abs(value * 100 - round(value * 100)) > 1e-9:
            return None, (
                f"{spec.label} may have at most two decimal places."
            )
        number = round(float(value), 2)
        if number == int(number):
            number = int(number)
    if not spec.minimum <= number <= spec.maximum:
        return None, (
            f"{spec.label} must be between "
            f"{_format_bound(spec.minimum)} and "
            f"{_format_bound(spec.maximum)}."
        )
    return number, None


def _format_bound(value: float) -> str:
    return f"{value:g}"


def _cross_field_problems(
    values: Mapping[str, Any],
) -> list[tuple[str | None, str]]:
    problems: list[tuple[str | None, str]] = []

    # tmpfs pages count against the container's memory limit.
    if values["tmp_mib"] >= values["memory_mib"]:
        problems.append((
            "tmp_mib",
            "Temporary space must be smaller than memory, because it "
            "is counted against the container's memory limit.",
        ))

    for analyzer in ("capa", "floss"):
        per_file = values[f"{analyzer}_file_timeout_seconds"]
        total = values[f"{analyzer}_total_timeout_seconds"]
        if per_file > total:
            problems.append((
                f"{analyzer}_file_timeout_seconds",
                f"The {analyzer} per-file timeout cannot exceed the "
                f"{analyzer} total budget.",
            ))

    if values["max_file_gib"] > values["max_total_gib"]:
        problems.append((
            "max_file_gib",
            "Maximum file size cannot exceed maximum total size.",
        ))

    # If Docker kills the container before the analyzer budgets run out,
    # the whole report is lost instead of a partial one being written.
    required = (
        values["capa_total_timeout_seconds"]
        + values["floss_total_timeout_seconds"]
        + HOST_TIMEOUT_MARGIN_SECONDS
    )
    if values["host_timeout_seconds"] < required:
        problems.append((
            "host_timeout_seconds",
            "Host time limit must be at least "
            f"{_format_duration(required)} for these analyzer budgets.",
        ))

    return problems


def _format_duration(seconds: int) -> str:
    hours, remainder = divmod(int(seconds), 3600)
    minutes = remainder // 60
    if hours and minutes:
        return f"{hours} h {minutes} min"
    if hours:
        return f"{hours} h"
    return f"{minutes} min"


def resolve_profile(
    base: str = DEFAULT_PRESET,
    overrides: Mapping[str, object] | None = None,
) -> ResourceProfile:
    """Resolve a preset plus optional overrides into a valid profile.

    Any override makes the profile "custom". Unknown fields are rejected
    rather than ignored, so nothing unvalidated can reach Docker.
    """

    if base not in PRESETS:
        raise ResourceProfileError([(
            None,
            f"Unknown resource profile '{base}'.",
        )])

    overrides = overrides or {}
    if not isinstance(overrides, Mapping):
        raise ResourceProfileError([(
            None,
            "Resource overrides must be an object.",
        )])

    problems: list[tuple[str | None, str]] = []
    unknown = sorted(str(key) for key in overrides if key not in FIELDS)
    for key in unknown:
        problems.append((None, f"Unknown resource setting '{key}'."))

    values: dict[str, Any] = dict(PRESETS[base])
    for name, raw in overrides.items():
        if name not in FIELDS:
            continue
        values[name] = raw

    checked: dict[str, Any] = {}
    for name in FIELDS:
        number, problem = _check_value(name, values[name])
        if problem is not None:
            problems.append((name, problem))
        else:
            checked[name] = number

    if not problems:
        problems.extend(_cross_field_problems(checked))
    if problems:
        raise ResourceProfileError(problems)

    return ResourceProfile(
        name=CUSTOM if overrides else base,
        base=base,
        **checked,
    )


def profile_from_dict(data: object) -> ResourceProfile:
    """Rebuild a profile from ``to_dict`` output, validating everything.

    Used by the container, which must not trust the host's values.
    """

    if not isinstance(data, Mapping):
        raise ResourceProfileError([(None, "Profile must be an object.")])
    expected = {"schema_version", "name", "base", "values"}
    if set(data) != expected:
        raise ResourceProfileError([(
            None,
            "Profile has missing or unexpected keys.",
        )])
    if data["schema_version"] != SCHEMA_VERSION:
        raise ResourceProfileError([(
            None,
            "Unsupported resource profile schema version.",
        )])

    base = data["base"]
    name = data["name"]
    values = data["values"]
    if not isinstance(base, str) or not isinstance(name, str):
        raise ResourceProfileError([(None, "Invalid profile name.")])
    if not isinstance(values, Mapping) or set(values) != set(FIELDS):
        raise ResourceProfileError([(
            None,
            "Profile values must list every resource setting.",
        )])

    profile = resolve_profile(base, values)
    if name == base:
        # A preset name must carry exactly the preset's values.
        if profile.changed_fields():
            raise ResourceProfileError([(
                None,
                f"Profile values do not match preset '{base}'.",
            )])
        return resolve_profile(base)
    if name != CUSTOM:
        raise ResourceProfileError([(None, "Invalid profile name.")])
    return profile


def check_capacity(
    profile: ResourceProfile,
    *,
    cpus_available: float,
    memory_bytes_available: int,
) -> list[str]:
    """Reject profiles Docker cannot satisfy; return warnings otherwise.

    Capacity comes from Docker rather than the host, because Docker
    Desktop's virtual machine can be smaller than the machine.
    """

    problems: list[tuple[str | None, str]] = []
    if profile.cpus > cpus_available:
        problems.append((
            "cpus",
            f"Docker has {cpus_available:g} CPUs available, but the "
            f"profile requests {profile.cpus:g}.",
        ))
    requested = profile.memory_mib * _MIB
    if requested > memory_bytes_available:
        problems.append((
            "memory_mib",
            f"Docker has {memory_bytes_available / _GIB:.1f} GiB of "
            f"memory available, but the profile requests "
            f"{requested / _GIB:.1f} GiB.",
        ))
    if problems:
        raise ResourceProfileError(problems)

    warnings: list[str] = []
    if requested > memory_bytes_available * MEMORY_WARNING_FRACTION:
        warnings.append(
            "The profile requests more than "
            f"{int(MEMORY_WARNING_FRACTION * 100)}% of the memory "
            "available to Docker, which may slow the rest of the system."
        )
    return warnings