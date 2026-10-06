from __future__ import annotations

import dataclasses
import json
import unittest

from static_triage.config import ScanLimits
from static_triage.resource_profiles import (
    CUSTOM,
    DEFAULT_PRESET,
    FIELDS,
    PRESETS,
    ResourceProfileError,
    check_capacity,
    profile_from_dict,
    resolve_profile,
)

GIB = 1024**3


def problem_fields(error: ResourceProfileError) -> set[str | None]:
    return {field for field, _ in error.problems}


class PresetTests(unittest.TestCase):
    def test_every_preset_resolves(self) -> None:
        for name in PRESETS:
            with self.subTest(preset=name):
                profile = resolve_profile(name)
                self.assertEqual(profile.name, name)
                self.assertEqual(profile.base, name)
                self.assertFalse(profile.is_custom)
                self.assertEqual(profile.changed_fields(), {})

    def test_presets_define_every_field(self) -> None:
        for name, values in PRESETS.items():
            with self.subTest(preset=name):
                self.assertEqual(set(values), set(FIELDS))

    def test_default_is_balanced(self) -> None:
        self.assertEqual(DEFAULT_PRESET, "balanced")
        self.assertEqual(resolve_profile().name, "balanced")

    def test_balanced_reproduces_pre_profile_container(self) -> None:
        profile = resolve_profile("balanced")
        self.assertEqual(profile.cpus, 2)
        self.assertEqual(profile.memory_mib, 4096)
        self.assertEqual(profile.pids_limit, 256)
        self.assertEqual(profile.tmp_mib, 512)
        self.assertEqual(profile.host_timeout_seconds, 4 * 60 * 60)

    def test_balanced_reproduces_pre_profile_scan_limits(self) -> None:
        self.assertEqual(
            resolve_profile("balanced").scan_limits(),
            ScanLimits(),
        )

    def test_presets_keep_per_file_timeouts(self) -> None:
        for name in PRESETS:
            with self.subTest(preset=name):
                profile = resolve_profile(name)
                self.assertEqual(profile.capa_file_timeout_seconds, 300)
                self.assertEqual(profile.floss_file_timeout_seconds, 600)

    def test_presets_scale_in_order(self) -> None:
        low = resolve_profile("constrained")
        mid = resolve_profile("balanced")
        high = resolve_profile("high")
        for field in ("cpus", "memory_mib", "capa_total_timeout_seconds"):
            with self.subTest(field=field):
                self.assertLess(getattr(low, field), getattr(mid, field))
                self.assertLess(getattr(mid, field), getattr(high, field))

    def test_profiles_are_immutable(self) -> None:
        profile = resolve_profile()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            profile.cpus = 8  # type: ignore[misc]


class OverrideTests(unittest.TestCase):
    def test_override_makes_custom_and_records_change(self) -> None:
        profile = resolve_profile("balanced", {"cpus": 3})
        self.assertEqual(profile.name, CUSTOM)
        self.assertEqual(profile.base, "balanced")
        self.assertTrue(profile.is_custom)
        self.assertEqual(profile.cpus, 3)
        self.assertEqual(profile.changed_fields(), {"cpus": 3})
        self.assertEqual(profile.memory_mib, 4096)

    def test_custom_can_change_per_file_timeouts(self) -> None:
        profile = resolve_profile(
            "balanced",
            {"capa_file_timeout_seconds": 150},
        )
        self.assertEqual(
            profile.scan_limits().capa_file_timeout_seconds,
            150.0,
        )

    def test_fractional_cpus(self) -> None:
        self.assertEqual(resolve_profile("balanced", {"cpus": 1.5}).cpus, 1.5)
        with self.assertRaises(ResourceProfileError):
            resolve_profile("balanced", {"cpus": 1.505})

    def test_unknown_preset_rejected(self) -> None:
        for name in ("turbo", "custom", "", "Balanced"):
            with self.subTest(name=name):
                with self.assertRaises(ResourceProfileError):
                    resolve_profile(name)

    def test_unknown_override_rejected_not_ignored(self) -> None:
        for key in ("network", "privileged", "cap_add", "Cpus"):
            with self.subTest(key=key):
                with self.assertRaises(ResourceProfileError) as raised:
                    resolve_profile("balanced", {key: 1})
                self.assertIn(key, str(raised.exception))

    def test_wrong_types_rejected(self) -> None:
        bad = [
            ("memory_mib", True),
            ("memory_mib", 4096.0),
            ("memory_mib", "4096"),
            ("memory_mib", None),
            ("cpus", False),
            ("cpus", "2"),
            ("cpus", float("nan")),
            ("cpus", float("inf")),
        ]
        for field, value in bad:
            with self.subTest(field=field, value=value):
                with self.assertRaises(ResourceProfileError) as raised:
                    resolve_profile("balanced", {field: value})
                self.assertIn(field, problem_fields(raised.exception))

    def test_bounds_enforced_for_every_field(self) -> None:
        for field, spec in FIELDS.items():
            for value in (spec.minimum - 1, spec.maximum + 1):
                if spec.kind == "int":
                    value = int(value)
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ResourceProfileError) as raised:
                        resolve_profile("high", {field: value})
                    self.assertIn(field, problem_fields(raised.exception))

    def test_overrides_must_be_mapping(self) -> None:
        with self.assertRaises(ResourceProfileError):
            resolve_profile("balanced", [("cpus", 2)])  # type: ignore[arg-type]

    def test_all_problems_reported_together(self) -> None:
        with self.assertRaises(ResourceProfileError) as raised:
            resolve_profile(
                "balanced",
                {"cpus": 0, "pids_limit": 1, "bogus": 1},
            )
        fields = problem_fields(raised.exception)
        self.assertIn("cpus", fields)
        self.assertIn("pids_limit", fields)
        self.assertIn(None, fields)


class CrossFieldTests(unittest.TestCase):
    def test_tmp_must_be_smaller_than_memory(self) -> None:
        with self.assertRaises(ResourceProfileError) as raised:
            resolve_profile("balanced", {"tmp_mib": 4096})
        self.assertEqual(problem_fields(raised.exception), {"tmp_mib"})

    def test_per_file_timeout_cannot_exceed_total(self) -> None:
        with self.assertRaises(ResourceProfileError) as raised:
            resolve_profile(
                "balanced",
                {
                    "capa_file_timeout_seconds": 600,
                    "capa_total_timeout_seconds": 300,
                },
            )
        self.assertEqual(
            problem_fields(raised.exception),
            {"capa_file_timeout_seconds"},
        )

    def test_file_size_cannot_exceed_total_size(self) -> None:
        with self.assertRaises(ResourceProfileError) as raised:
            resolve_profile(
                "balanced",
                {"max_file_gib": 8, "max_total_gib": 4},
            )
        self.assertEqual(problem_fields(raised.exception), {"max_file_gib"})

    def test_host_limit_must_cover_analyzer_budgets(self) -> None:
        # 1 h + 1 h + 30 min margin = 2 h 30 min required.
        with self.assertRaises(ResourceProfileError) as raised:
            resolve_profile(
                "balanced",
                {"host_timeout_seconds": 2 * 60 * 60},
            )
        self.assertEqual(
            problem_fields(raised.exception),
            {"host_timeout_seconds"},
        )
        self.assertIn("2 h 30 min", str(raised.exception))
        resolve_profile(
            "balanced",
            {"host_timeout_seconds": int(2.5 * 60 * 60)},
        )

    def test_raising_budgets_requires_raising_host_limit(self) -> None:
        with self.assertRaises(ResourceProfileError):
            resolve_profile(
                "balanced",
                {"capa_total_timeout_seconds": 3 * 60 * 60},
            )
        resolve_profile(
            "balanced",
            {
                "capa_total_timeout_seconds": 3 * 60 * 60,
                "host_timeout_seconds": int(4.5 * 60 * 60),
            },
        )


class SerializationTests(unittest.TestCase):
    def roundtrip(self, profile):
        return profile_from_dict(json.loads(json.dumps(profile.to_dict())))

    def test_preset_roundtrip(self) -> None:
        for name in PRESETS:
            with self.subTest(preset=name):
                profile = resolve_profile(name)
                self.assertEqual(self.roundtrip(profile), profile)

    def test_custom_roundtrip(self) -> None:
        profile = resolve_profile(
            "high",
            {"cpus": 2.5, "capa_file_timeout_seconds": 120},
        )
        self.assertEqual(self.roundtrip(profile), profile)

    def test_tampered_preset_values_rejected(self) -> None:
        data = resolve_profile("balanced").to_dict()
        data["values"]["memory_mib"] = 8192
        with self.assertRaises(ResourceProfileError):
            profile_from_dict(data)

    def test_out_of_bounds_values_rejected(self) -> None:
        data = resolve_profile("balanced", {"cpus": 3}).to_dict()
        data["values"]["pids_limit"] = 1_000_000
        with self.assertRaises(ResourceProfileError):
            profile_from_dict(data)

    def test_structural_tampering_rejected(self) -> None:
        good = resolve_profile("balanced").to_dict()
        cases = {
            "not a dict": [],
            "wrong version": {**good, "schema_version": 2},
            "extra key": {**good, "privileged": True},
            "missing key": {
                key: value for key, value in good.items() if key != "base"
            },
            "unknown name": {**good, "name": "turbo"},
            "unknown base": {**good, "base": "turbo"},
            "missing value": {
                **good,
                "values": {
                    key: value
                    for key, value in good["values"].items()
                    if key != "cpus"
                },
            },
            "extra value": {
                **good,
                "values": {**good["values"], "network": "host"},
            },
            "values not a dict": {**good, "values": []},
        }
        for label, data in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(ResourceProfileError):
                    profile_from_dict(data)


class CapacityTests(unittest.TestCase):
    def test_fits_without_warning(self) -> None:
        self.assertEqual(
            check_capacity(
                resolve_profile("balanced"),
                cpus_available=8,
                memory_bytes_available=16 * GIB,
            ),
            [],
        )

    def test_too_many_cpus_rejected(self) -> None:
        with self.assertRaises(ResourceProfileError) as raised:
            check_capacity(
                resolve_profile("high"),
                cpus_available=2,
                memory_bytes_available=64 * GIB,
            )
        self.assertEqual(problem_fields(raised.exception), {"cpus"})

    def test_too_much_memory_rejected(self) -> None:
        with self.assertRaises(ResourceProfileError) as raised:
            check_capacity(
                resolve_profile("high"),
                cpus_available=16,
                memory_bytes_available=6 * GIB,
            )
        self.assertEqual(problem_fields(raised.exception), {"memory_mib"})

    def test_large_share_of_memory_warns(self) -> None:
        warnings = check_capacity(
            resolve_profile("balanced"),
            cpus_available=8,
            memory_bytes_available=5 * GIB,
        )
        self.assertEqual(len(warnings), 1)
        self.assertIn("75%", warnings[0])


if __name__ == "__main__":
    unittest.main()