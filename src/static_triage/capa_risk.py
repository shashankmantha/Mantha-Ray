"""Deterministic, explainable risk weighting for capa capabilities."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable


RISK_POLICY_VERSION = "2"
REVIEW_SCORE = 6
HIGH_CONCERN_SCORE = 10
MAX_TOTAL_SCORE = 100

# capa rules that sound alarming but are routine in games, engines and media
# libraries. They never count towards a suspicious combination and only add
# context to a file's score.
ROUTINE_RULES = frozenset({
    # Any JIT (LuaJIT, Mono, .NET) or game engine manages its own memory.
    "allocate or change rwx memory",
    "allocate user process rwx memory",
    "free user process memory",
    "attach user process memory",
    "add value to global atom table",
    # This is how games read the keyboard and controllers.
    "log keystrokes via raw input data",
    "log keystrokes via direct input",
    "log keystrokes via polling",
    "register raw input devices",
    # Ordinary features: screenshots, copy and paste.
    "capture screenshot",
    "check clipboard data",
    "clear clipboard data",
    "open clipboard",
    "read clipboard data",
    "write clipboard data",
    "list drag and drop files",
    # CPU feature detection (FFmpeg and most engines).
    "reference processor manufacturer constants",
    "reference startup folder",
    "get startup folder",
})

# Rules legitimate software essentially never needs: each alone is enough.
STRONG_SINGLE_RULES = frozenset({
    "delete volume shadow copies",
    "delete windows backup catalog",
    "disable automatic windows recovery features",
    "delete drive layout via ioctl",
    "overwrite master boot record (mbr)",
    "use process doppelgänging",
    "process ghostly hollowing",
    "use process replacement",
    "patch antimalware scan interface function",
    "patch event tracing for windows function",
    "disable windows defender features via registry on windows",
    "steal keepass passwords using keefarce",
})

# Groups a file's capabilities fall into, by capa namespace or ATT&CK
# technique. A suspicious combination needs two different groups in the same
# file (see COMBINATIONS).
_GROUP_NAMESPACES = {
    "injection": ("host-interaction/process/inject", "load-code/shellcode"),
    "credentials": ("collection/browser", "collection/password-manager"),
    "spying": (
        "collection/keylog",
        "host-interaction/clipboard",
        "collection/webcam",
        "collection/microphone",
    ),
    "persistence": ("persistence/",),
    "remote-shell": ("communication/c2/shell",),
    "file-transfer": ("communication/c2/file-transfer",),
    "network": ("communication/",),
    "evasion": (
        "anti-analysis/anti-av",
        "anti-analysis/anti-vm",
        "impact/features",
        "host-interaction/uac/bypass",
    ),
    "privilege": ("host-interaction/uac/bypass",),
    "recovery-impact": ("impact/inhibit-system-recovery", "impact/wipe-disk"),
    "mining": ("impact/cryptocurrency",),
}
_GROUP_ATTACK = {
    "injection": ("T1055",),
    "credentials": ("T1003", "T1555", "T1552", "T1212"),
    "privilege": ("T1548",),
    "recovery-impact": ("T1490", "T1561"),
    "mining": ("T1496",),
}


@dataclass(frozen=True, slots=True)
class _Combination:
    identifier: str
    description: str
    first: frozenset[str]
    second: frozenset[str]


COMBINATIONS = (
    _Combination(
        "injection-with-payload",
        "injects code into other processes and also steals, spies, persists, "
        "hides or opens a remote shell",
        frozenset({"injection"}),
        frozenset({"credentials", "spying", "persistence", "remote-shell", "evasion"}),
    ),
    _Combination(
        "credential-theft-and-network",
        "reads stored passwords or browser logins and can send data out",
        frozenset({"credentials"}),
        frozenset({"network", "file-transfer", "remote-shell"}),
    ),
    _Combination(
        "spying-and-network",
        "hooks the keyboard or watches the clipboard, webcam or microphone, "
        "and can send data out",
        frozenset({"spying"}),
        frozenset({"network", "file-transfer", "remote-shell"}),
    ),
    _Combination(
        "persistence-with-payload",
        "makes itself start automatically and also opens a remote shell, hides, "
        "steals, spies or raises its privileges",
        frozenset({"persistence"}),
        frozenset({"remote-shell", "evasion", "credentials", "spying", "privilege"}),
    ),
    _Combination(
        "mining-with-stealth",
        "references cryptocurrency mining and hides, persists, injects or "
        "downloads more",
        frozenset({"mining"}),
        frozenset({"evasion", "persistence", "injection", "file-transfer"}),
    ),
    _Combination(
        "evasion-with-payload",
        "checks for antivirus or virtual machines and also steals, spies or "
        "opens a remote shell",
        frozenset({"evasion"}),
        frozenset({"credentials", "spying", "remote-shell"}),
    ),
)


def capability_groups(
    name: str,
    namespace: str | None,
    attack_ids: Iterable[str] = (),
) -> frozenset[str]:
    """The groups one capa rule belongs to; routine rules belong to none."""

    if name.casefold().strip() in ROUTINE_RULES:
        return frozenset()
    space = (namespace or "").casefold().strip()
    groups = {
        group
        for group, prefixes in _GROUP_NAMESPACES.items()
        if any(space.startswith(prefix) for prefix in prefixes)
    }
    identifiers = [identifier.upper() for identifier in attack_ids]
    for group, techniques in _GROUP_ATTACK.items():
        if any(
            identifier.startswith(technique)
            for identifier in identifiers
            for technique in techniques
        ):
            groups.add(group)
    if groups & {"remote-shell", "file-transfer"}:
        groups.discard("network")
    return frozenset(groups)


@dataclass(frozen=True, slots=True)
class SuspiciousCombination:
    """Capabilities in one file that together look like malware."""

    identifier: str
    description: str
    capabilities: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.identifier,
            "description": self.description,
            "capabilities": list(self.capabilities),
        }


def find_combinations(
    capabilities: Iterable[tuple[str, str | None, Iterable[str]]],
) -> tuple[SuspiciousCombination, ...]:
    """Suspicious combinations among one file's (name, namespace, ATT&CK ids)."""

    by_group: dict[str, list[str]] = {}
    strong: list[str] = []
    for name, namespace, attack_ids in capabilities:
        if name.casefold().strip() in STRONG_SINGLE_RULES and name not in strong:
            strong.append(name)
        for group in capability_groups(name, namespace, tuple(attack_ids)):
            members = by_group.setdefault(group, [])
            if name not in members:
                members.append(name)

    found = [
        SuspiciousCombination(
            "strong-indicator",
            f"{name}: rarely, if ever, needed by legitimate software",
            (name,),
        )
        for name in strong
    ]
    for combo in COMBINATIONS:
        first = list(dict.fromkeys(
            name for group in sorted(combo.first) for name in by_group.get(group, [])
        ))
        second = list(dict.fromkeys(
            name
            for group in sorted(combo.second)
            for name in by_group.get(group, [])
            if name not in first
        ))
        if first and second:
            found.append(SuspiciousCombination(
                combo.identifier,
                combo.description,
                tuple(first[:3] + second[:3]),
            ))
    return tuple(found)


class CapaRiskLevel(StrEnum):
    """Normalized risk bands used by reports and verdict logic."""

    INFORMATIONAL = "informational"
    LOW = "low"
    REVIEW = "review"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class CapabilityRisk:
    """Risk contribution from one capa capability."""

    name: str
    namespace: str | None
    score: int
    base_score: int
    repetition_bonus: int
    level: CapaRiskLevel
    policy: str
    reason: str

    @property
    def identity(self) -> tuple[str, str]:
        """Return a stable identity for duplicate suppression."""

        return (
            self.name.casefold().strip(),
            (self.namespace or "").casefold().strip(),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "score": self.score,
            "base_score": self.base_score,
            "repetition_bonus": self.repetition_bonus,
            "level": self.level.value,
            "policy": self.policy,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class CapaRiskSummary:
    """File- or case-level capa risk.

    The score ranks files for review. Only suspicious combinations raise a
    case above Needs Review, and only to Suspicious Capabilities: capa
    describes what code can do, not what it is for.
    """

    score: int
    level: CapaRiskLevel
    review_required: bool
    high_concern: bool
    unique_capabilities: int
    # Suspicious combinations, as (relative path, or "" for a single file).
    combinations: tuple[tuple[str, SuspiciousCombination], ...] = ()

    @property
    def suspicious(self) -> bool:
        return bool(self.combinations)

    def to_dict(self) -> dict[str, object]:
        return {
            "score": self.score,
            "level": self.level.value,
            "review_required": self.review_required,
            # Kept for older readers; since policy 2 it means the same as
            # "suspicious". capa alone never makes a case High Concern.
            "high_concern": self.high_concern,
            "suspicious": self.suspicious,
            "combinations": [
                {"relative_path": path, **combo.to_dict()} if path else combo.to_dict()
                for path, combo in self.combinations
            ],
            "unique_capabilities": self.unique_capabilities,
            "policy_version": RISK_POLICY_VERSION,
            "thresholds": {
                "review": REVIEW_SCORE,
                "high_concern": HIGH_CONCERN_SCORE,
            },
        }


@dataclass(frozen=True, slots=True)
class _RiskPolicy:
    identifier: str
    score: int
    reason: str
    patterns: tuple[str, ...]


_INFORMATIONAL_IDENTITIES = frozenset(
    {
        (
            "terminate process",
            "host-interaction/process/terminate",
        ),
    }
)


_POLICIES = (
    _RiskPolicy(
        identifier="critical-impact",
        score=10,
        reason=(
            "Capability is strongly associated with credential theft, "
            "code injection, ransomware, or deep system compromise."
        ),
        patterns=(
            "process/inject",
            "process injection",
            "inject code",
            "credential",
            "dump lsass",
            "keylog",
            "ransom",
            "encrypt file",
            "rootkit",
            "bootkit",
        ),
    ),
    _RiskPolicy(
        identifier="adversary-control",
        score=7,
        reason=(
            "Capability can establish control, persistence, evasion, "
            "privilege, lateral movement, or data exfiltration."
        ),
        patterns=(
            "command-and-control",
            "command and control",
            "communication/c2",
            "persistence",
            "anti-analysis",
            "anti-debug",
            "defense evasion",
            "privilege escalation",
            "lateral movement",
            "remote access",
            "exfiltration",
        ),
    ),
    _RiskPolicy(
        identifier="active-behavior",
        score=4,
        reason=(
            "Capability performs active communication, execution, "
            "system modification, discovery, or data transformation."
        ),
        patterns=(
            "communication/http",
            "communication/dns",
            "network/connect",
            "send http",
            "connect to",
            "download",
            "execute",
            "command shell",
            "spawn process",
            "create process",
            "modify registry",
            "scheduled task",
            "create service",
            "enumerate process",
            "process discovery",
            "system information",
            "decode data",
            "decrypt data",
        ),
    ),
)


def risk_level(score: int) -> CapaRiskLevel:
    """Map a non-negative score to its documented risk band."""

    if score < 0:
        raise ValueError("capa risk score cannot be negative")

    if score >= HIGH_CONCERN_SCORE:
        return CapaRiskLevel.HIGH

    if score >= REVIEW_SCORE:
        return CapaRiskLevel.REVIEW

    if score >= 3:
        return CapaRiskLevel.LOW

    return CapaRiskLevel.INFORMATIONAL


def assess_capability(
    name: str,
    namespace: str | None,
    match_count: int,
) -> CapabilityRisk:
    """Assign a deterministic risk contribution to one capa rule."""

    if match_count < 0:
        raise ValueError("capa match count cannot be negative")

    normalized_name = name.casefold().strip()
    normalized_namespace = (namespace or "").casefold().strip()
    identity = (normalized_name, normalized_namespace)

    if normalized_name in ROUTINE_RULES:
        base_score = 1
        policy = "routine-in-legitimate-software"
        reason = (
            "Routine in games, engines and media libraries (input handling, "
            "JIT memory, screenshots, CPU detection); context only."
        )
    elif normalized_name in STRONG_SINGLE_RULES:
        base_score = 10
        policy = "strong-indicator"
        reason = "Rarely, if ever, needed by legitimate software."
    elif identity in _INFORMATIONAL_IDENTITIES:
        base_score = 1
        policy = "common-lifecycle"
        reason = (
            "Common process-lifecycle behavior; it is not suspicious "
            "without stronger supporting capabilities."
        )
    else:
        searchable = f"{normalized_name} {normalized_namespace}"

        matches = [
            item
            for item in _POLICIES
            if any(
                pattern in searchable
                for pattern in item.patterns
            )
        ]

        if matches:
            selected = max(
                matches,
                key=lambda item: item.score,
            )

            base_score = selected.score
            policy = selected.identifier
            reason = selected.reason
        else:
            base_score = 1
            policy = "generic-capability"
            reason = (
                "Generic static capability; retain it as context but "
                "do not escalate on this match alone."
            )

    # Repetition is weak supporting evidence. It can add at most one
    # point and never inflates generic/informational capabilities.
    repetition_bonus = int(
        base_score >= 4
        and match_count > 1
    )

    score = base_score + repetition_bonus

    return CapabilityRisk(
        name=name,
        namespace=namespace,
        score=score,
        base_score=base_score,
        repetition_bonus=repetition_bonus,
        level=risk_level(score),
        policy=policy,
        reason=reason,
    )


def summarize_risk(
    assessments: Iterable[CapabilityRisk],
    combinations: Iterable[SuspiciousCombination] = (),
) -> CapaRiskSummary:
    """One file's capabilities: a bounded score plus suspicious combinations."""

    unique: dict[
        tuple[str, str],
        CapabilityRisk,
    ] = {}

    for assessment in assessments:
        current = unique.get(assessment.identity)

        if (
            current is None
            or assessment.score > current.score
        ):
            unique[assessment.identity] = assessment

    score = min(
        sum(
            assessment.score
            for assessment in unique.values()
        ),
        MAX_TOTAL_SCORE,
    )
    found = tuple(("", combo) for combo in combinations)

    return CapaRiskSummary(
        score=score,
        level=risk_level(score),
        review_required=score >= REVIEW_SCORE or bool(found),
        high_concern=bool(found),
        unique_capabilities=len(unique),
        combinations=found,
    )


def summarize_files(
    files: Iterable[tuple[str, CapaRiskSummary]],
) -> CapaRiskSummary:
    """A case's capa risk: the worst single file, never a sum across files.

    Adding capabilities up across a whole folder made any large program (a
    game with an engine, codecs and DRM) look malicious.
    """

    worst: CapaRiskSummary | None = None
    combinations: list[tuple[str, SuspiciousCombination]] = []
    review = False
    for path, summary in files:
        if worst is None or summary.score > worst.score:
            worst = summary
        review = review or summary.review_required
        combinations.extend((path, combo) for _, combo in summary.combinations)
    score = worst.score if worst is not None else 0
    return CapaRiskSummary(
        score=score,
        level=risk_level(score),
        review_required=review,
        high_concern=bool(combinations),
        unique_capabilities=worst.unique_capabilities if worst is not None else 0,
        combinations=tuple(combinations),
    )
