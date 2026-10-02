"""Lab evaluation foundation.

The AI engine must be benchmarkable in isolated labs *before* it is trusted
near real targets (and before Discovery learns which public signals matter).
This module provides:

- :class:`LabScenario` — a lab exercise whose targets must all be loopback or
  private lab addresses; anything else is rejected at construction time;
- :class:`EvaluationMetrics` / :class:`EvaluationRecord` — the benchmark
  schema the engine is scored on;
- :class:`LabEvaluationHarness` — the only run path, and it is lab-only.

No real-target adapters exist here, by design.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

from .ai.orchestration import RunContext
from .scope import ScopePolicy, ScopeReason

_LAB_REASONS = {ScopeReason.LOOPBACK, ScopeReason.PRIVATE_LAB}
_LAB_SCOPE = ScopePolicy(
    allow_private_lab=True,
    explicit_hosts=frozenset(),
    explicit_networks=(),
    require_authorization_for_public=True,
)


class LabIsolationError(PermissionError):
    """A scenario or run tried to leave the isolated lab."""


def assert_lab_target(value: str) -> str:
    """Return the normalized host if it is a lab target, else fail closed."""
    from .models import Target

    decision = _LAB_SCOPE.decide(Target(value))
    if not decision.allowed or decision.reason not in _LAB_REASONS:
        raise LabIsolationError(
            f"target {value!r} is not an isolated lab target "
            f"(reason: {decision.reason.value})"
        )
    assert decision.normalized_host is not None
    return decision.normalized_host


@dataclass(frozen=True)
class ExpectedFinding:
    """Ground truth planted in a lab scenario, used for scoring."""

    identifier: str
    title: str
    capability_id: str
    severity: str


@dataclass(frozen=True)
class LabScenario:
    scenario_id: str
    name: str
    targets: tuple[str, ...]
    expected_findings: tuple[ExpectedFinding, ...] = ()
    description: str = ""

    def __post_init__(self) -> None:
        if not self.targets:
            raise ValueError("a lab scenario requires at least one target")
        normalized = tuple(assert_lab_target(t) for t in self.targets)
        object.__setattr__(self, "targets", normalized)


@dataclass(frozen=True)
class EvaluationMetrics:
    """What the engine is objectively scored on per lab run."""

    valid_findings: int = 0
    invalid_findings: int = 0
    missed_findings: int = 0
    coverage_assessed: int = 0
    coverage_unknown: int = 0
    evidence_quality: float = 0.0       # 0..1 rubric score
    reproducibility: float = 0.0        # 0..1 fraction of findings reproduced
    scope_violations: int = 0
    policy_violations: int = 0
    human_interventions: int = 0
    tool_calls: int = 0
    runtime_seconds: float = 0.0
    compute_cost_usd: float = 0.0
    remediation_quality: float = 0.0    # 0..1 rubric score
    retest_correctness: float = 0.0     # 0..1 fraction of correct retest verdicts

    @property
    def false_positive_rate(self) -> float:
        total = self.valid_findings + self.invalid_findings
        return (self.invalid_findings / total) if total else 0.0

    def validate(self) -> None:
        for name in ("evidence_quality", "reproducibility", "remediation_quality",
                     "retest_correctness"):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")
        for name in ("valid_findings", "invalid_findings", "missed_findings",
                     "coverage_assessed", "coverage_unknown", "scope_violations",
                     "policy_violations", "human_interventions", "tool_calls"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} cannot be negative")


@dataclass(frozen=True)
class EvaluationRecord:
    record_id: str
    scenario_id: str
    run_id: str
    engine_version: str
    model_bindings: tuple[tuple[str, str], ...]  # (role, provider/model) pairs
    metrics: EvaluationMetrics
    created_at: str
    notes: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["metrics"]["false_positive_rate"] = self.metrics.false_positive_rate
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def score_findings(
    expected: tuple[ExpectedFinding, ...], found_identifiers: tuple[str, ...]
) -> tuple[int, int, int]:
    """Return (valid, invalid, missed) for found check identifiers vs ground truth."""
    found = set(found_identifiers)
    truth = {item.identifier for item in expected}
    return len(found & truth), len(found - truth), len(truth - found)


@dataclass
class LabEvaluationHarness:
    """Creates lab-only run contexts and records benchmark results.

    This is deliberately the *only* way evaluation runs are created. It cannot
    produce a context for anything but an isolated lab scenario.
    """

    engine_version: str = "m1-dev"
    records: list[EvaluationRecord] = field(default_factory=list)

    def start_run(self, scenario: LabScenario) -> RunContext:
        for target in scenario.targets:
            assert_lab_target(target)
        return RunContext.for_lab(run_id=str(uuid4()), engagement_id=scenario.scenario_id)

    def record(
        self,
        scenario: LabScenario,
        context: RunContext,
        metrics: EvaluationMetrics,
        model_bindings: tuple[tuple[str, str], ...] = (),
        notes: str = "",
    ) -> EvaluationRecord:
        if not context.is_lab:
            raise LabIsolationError("evaluation records are lab-only")
        metrics.validate()
        record = EvaluationRecord(
            record_id=str(uuid4()),
            scenario_id=scenario.scenario_id,
            run_id=context.run_id,
            engine_version=self.engine_version,
            model_bindings=model_bindings,
            metrics=metrics,
            created_at=datetime.now(timezone.utc).isoformat(),
            notes=notes,
        )
        self.records.append(record)
        return record
