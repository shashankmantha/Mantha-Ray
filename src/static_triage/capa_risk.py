"""Deterministic, explainable risk weighting for capa capabilities."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable


RISK_POLICY_VERSION = "1"
REVIEW_SCORE = 6
HIGH_CONCERN_SCORE = 10
MAX_TOTAL_SCORE = 100


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
    """Case- or file-level aggregate capa risk."""

    score: int
    level: CapaRiskLevel
    review_required: bool
    high_concern: bool
    unique_capabilities: int

    def to_dict(self) -> dict[str, object]:
        return {
            "score": self.score,
            "level": self.level.value,
            "review_required": self.review_required,
            "high_concern": self.high_concern,
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

    if identity in _INFORMATIONAL_IDENTITIES:
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
) -> CapaRiskSummary:
    """Aggregate unique capa rules with a bounded total score."""

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

    level = risk_level(score)

    return CapaRiskSummary(
        score=score,
        level=level,
        review_required=score >= REVIEW_SCORE,
        high_concern=score >= HIGH_CONCERN_SCORE,
        unique_capabilities=len(unique),
    )