"""Finding prioritization and attack-chain correlation.

A list of findings is not an answer; an operator needs to know *what to fix
first* and *which weaknesses combine into something worse than their parts*.
This module turns raw findings into a ranked, correlated view.

Two jobs:

1. **Prioritize.** Each finding gets a deterministic priority score from its
   severity, whether the underlying issue is known to be exploited in the wild
   (carried in finding metadata by the advisory layer), and how exposed the
   asset is. The output is a stable "fix first" ordering.

2. **Correlate.** Known weakness combinations on the same asset are recognised
   as *chains* — e.g. exposed source-control metadata together with an exposed
   environment file is a credential-disclosure chain worth more than either
   finding alone. Chains are data-driven and conservative: a chain is only
   reported when every one of its required findings is present on one asset.

Everything here is pure computation over :class:`~lightup.models.Finding`
objects. No targets are touched and no network access happens.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .models import Finding, Severity

_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 25,
    Severity.MEDIUM: 12,
    Severity.LOW: 5,
    Severity.INFO: 1,
}

# Order used to break ties and to rank chain severity.
_SEVERITY_ORDER = {s: i for i, s in enumerate(
    (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL))}

KNOWN_EXPLOITED_BONUS = 30
EXPOSURE_BONUS = 10  # internet-facing / unauthenticated reach


def _is_known_exploited(finding: Finding) -> bool:
    value = finding.metadata.get("known_exploited")
    return value is True or str(value).lower() == "true"


def _is_externally_exposed(finding: Finding) -> bool:
    value = finding.metadata.get("exposure", "")
    return str(value).lower() in {"external", "internet", "unauthenticated"}


@dataclass(frozen=True)
class ScoredFinding:
    finding: Finding
    score: int
    rationale: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding.finding_id,
            "title": self.finding.title,
            "severity": self.finding.severity.value,
            "target": self.finding.target,
            "check_id": self.finding.metadata.get("check_id"),
            "score": self.score,
            "rationale": list(self.rationale),
        }


def score_finding(finding: Finding) -> ScoredFinding:
    base = _SEVERITY_WEIGHT[finding.severity]
    rationale = [f"severity={finding.severity.value} (+{base})"]
    score = base
    if _is_known_exploited(finding):
        score += KNOWN_EXPLOITED_BONUS
        rationale.append(f"known-exploited (+{KNOWN_EXPLOITED_BONUS})")
    if _is_externally_exposed(finding):
        score += EXPOSURE_BONUS
        rationale.append(f"externally-exposed (+{EXPOSURE_BONUS})")
    return ScoredFinding(finding, score, tuple(rationale))


def _finding_sort_key(scored: ScoredFinding) -> tuple:
    return (
        -scored.score,
        -_SEVERITY_ORDER[scored.finding.severity],
        scored.finding.target,
        scored.finding.finding_id,
    )


# --------------------------------------------------------------------------
# Attack chains
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ChainRule:
    chain_id: str
    name: str
    required_checks: frozenset[str]
    severity: Severity
    narrative: str


# Conservative, well-understood combinations. A chain fires only when every
# required check id is present on a single asset.
CHAIN_RULES: tuple[ChainRule, ...] = (
    ChainRule(
        "scm-plus-secret-disclosure",
        "Source exposure feeding secret disclosure",
        frozenset({"exposed-scm-metadata", "exposed-dotenv"}),
        Severity.CRITICAL,
        "Reconstructable server-side source plus an exposed environment file "
        "lets an attacker read code and the secrets it uses together.",
    ),
    ChainRule(
        "vuln-dependency-plus-stack-trace",
        "Fingerprintable vulnerable dependency with error disclosure",
        frozenset({"stack-trace-disclosure"}),
        Severity.HIGH,
        "Stack traces identify exact component versions, making a known "
        "advisory in a shipped dependency directly actionable.",
        # require_metadata handled below via extra predicate
    ),
    ChainRule(
        "diagnostics-plus-missing-cookie-protection",
        "Diagnostics exposure with weak session cookies",
        frozenset({"unauthenticated-diagnostics", "session-cookie-missing-httponly"}),
        Severity.HIGH,
        "An unauthenticated diagnostics endpoint plus script-readable session "
        "cookies broadens both reconnaissance and session-theft options.",
    ),
    ChainRule(
        "cors-plus-missing-cookie-protection",
        "Permissive CORS with weak session cookies",
        frozenset({"permissive-cors-reflection", "session-cookie-missing-samesite"}),
        Severity.HIGH,
        "Origin-reflecting CORS with credentials, combined with cookies sent "
        "cross-site, enables authenticated cross-origin requests.",
    ),
)


@dataclass(frozen=True)
class DetectedChain:
    chain_id: str
    name: str
    severity: Severity
    target: str
    narrative: str
    finding_ids: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "severity": self.severity.value,
            "target": self.target,
            "narrative": self.narrative,
            "finding_ids": list(self.finding_ids),
        }


def _checks_by_target(findings: Iterable[Finding]) -> dict[str, dict[str, list[Finding]]]:
    grouped: dict[str, dict[str, list[Finding]]] = {}
    for finding in findings:
        check = str(finding.metadata.get("check_id", "")) or finding.finding_id
        grouped.setdefault(finding.target, {}).setdefault(check, []).append(finding)
    return grouped


def detect_chains(findings: Iterable[Finding]) -> list[DetectedChain]:
    findings = list(findings)
    by_target = _checks_by_target(findings)
    vulnerable_dep_targets = {
        f.target for f in findings
        if str(f.metadata.get("check_id", "")).startswith("vulnerable-dependency")
        or f.metadata.get("advisory_id")
    }
    chains: list[DetectedChain] = []
    for target, checks in sorted(by_target.items()):
        present = set(checks)
        for rule in CHAIN_RULES:
            if not rule.required_checks <= present:
                continue
            if rule.chain_id == "vuln-dependency-plus-stack-trace" \
                    and target not in vulnerable_dep_targets:
                continue
            finding_ids = tuple(sorted(
                f.finding_id for check in rule.required_checks for f in checks[check]))
            chains.append(DetectedChain(rule.chain_id, rule.name, rule.severity,
                                        target, rule.narrative, finding_ids))
    return chains


@dataclass
class PrioritizationReport:
    scored: list[ScoredFinding] = field(default_factory=list)
    chains: list[DetectedChain] = field(default_factory=list)

    @property
    def fix_first(self) -> list[ScoredFinding]:
        return self.scored

    def to_dict(self) -> dict:
        by_target: dict[str, int] = {}
        for scored in self.scored:
            by_target[scored.finding.target] = by_target.get(scored.finding.target, 0) + 1
        return {
            "fix_first": [s.to_dict() for s in self.scored],
            "chains": [c.to_dict() for c in self.chains],
            "summary": {
                "total_findings": len(self.scored),
                "chains_detected": len(self.chains),
                "assets_affected": len(by_target),
                "top_score": self.scored[0].score if self.scored else 0,
            },
        }


def prioritize(findings: Iterable[Finding]) -> PrioritizationReport:
    """Rank findings 'fix first' and surface correlated attack chains."""
    findings = list(findings)
    scored = sorted((score_finding(f) for f in findings), key=_finding_sort_key)
    chains = detect_chains(findings)
    chains.sort(key=lambda c: (-_SEVERITY_ORDER[c.severity], c.target, c.chain_id))
    return PrioritizationReport(scored, chains)
