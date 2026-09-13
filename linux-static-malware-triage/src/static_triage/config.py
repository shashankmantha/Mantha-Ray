"""Scanner configuration and hard resource limits."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ScanLimits:
    """Hard resource limits applied during a scan."""

    # Inventory limits
    max_file_count: int = 25_000
    max_total_bytes: int = 100 * 1024**3
    max_file_bytes: int = 4 * 1024**3
    max_depth: int = 32
    hash_chunk_bytes: int = 1024 * 1024
    max_display_path_chars: int = 500

    # capa limits
    max_capa_files: int = 250
    capa_file_timeout_seconds: float = 300.0
    capa_total_timeout_seconds: float = 3_600.0
    capa_max_output_bytes: int = 16_000_000

    # FLOSS limits
    max_floss_files: int = 50
    floss_file_timeout_seconds: float = 600.0
    floss_total_timeout_seconds: float = 3_600.0
    floss_max_output_bytes: int = 16_000_000
    floss_max_strings: int = 2_000
    floss_max_string_chars: int = 4_096

    def validate(self) -> None:
        """Reject zero or negative limit values."""

        for field_name, value in asdict(self).items():
            if value <= 0:
                raise ValueError(
                    f"{field_name} must be greater than zero"
                )


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Paths and limits required to perform a scan."""

    staging_root: Path
    results_root: Path
    limits: ScanLimits = field(
        default_factory=ScanLimits
    )

    def validate(self) -> None:
        """Validate the complete scanner configuration."""

        self.limits.validate()