"""Role-routed review pipeline over assessment findings.

First real consumer of the Model Gateway: for each finding the **verifier**
role issues a verdict, the **remediation advisor** refines the fix advice, and
the **report synthesizer** writes a client-facing summary. Which model serves
which role is pure gateway configuration — tests and lab evaluation bind a
deterministic ScriptedProvider; production can bind real providers without
touching this module.

The pipeline only shapes text. It cannot execute anything: tool execution
stays behind the ToolExecutor's policy gate, and a verdict here never widens
scope, risk or authorization.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .gateway import (
    GatewayConfigurationError,
    ModelGateway,
    ModelMessage,
    ModelRole,
)

_VERIFIER_SYSTEM = (
    "You are the verifier of a security assessment. Judge whether the finding "
    "is supported by its evidence summary. Answer with one line starting with "
    "CONFIRMED, UNCERTAIN or REJECTED, then a short reason."
)
_REMEDIATION_SYSTEM = (
    "You are the remediation advisor. Improve the proposed fix: concrete "
    "steps, order of operations, and how to verify the fix afterwards."
)
_REPORT_SYSTEM = (
    "You are the report synthesizer. Write a short, calm, client-facing "
    "summary: what was assessed, what was found, what to do first. State "
    "explicitly when coverage is materially unknown; never claim everything "
    "was tested."
)


@dataclass(frozen=True)
class ReviewedFinding:
    title: str
    severity: str
    verdict: str
    remediation_advice: str


@dataclass(frozen=True)
class ReviewResult:
    findings: tuple[ReviewedFinding, ...]
    report: str
    model_bindings: tuple[tuple[str, str], ...]

    def to_dict(self) -> dict:
        return {
            "findings": [
                {"finding": f.title, "severity": f.severity, "verdict": f.verdict,
                 "remediation_advice": f.remediation_advice}
                for f in self.findings
            ],
            "report": self.report,
            "model_bindings": {role: model for role, model in self.model_bindings},
        }


class AssessmentReviewPipeline:
    """Runs verifier/remediation/report roles over a lab run's findings."""

    ROLES = (ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR, ModelRole.REPORT_SYNTHESIZER)

    def __init__(self, gateway: ModelGateway):
        # Fail closed at construction: every role this pipeline uses must be
        # bound before any review runs.
        self.gateway = gateway
        for role in self.ROLES:
            gateway.binding_for(role)

    def _complete_text(
        self,
        role: ModelRole,
        messages: tuple[ModelMessage, ...],
    ) -> str:
        """Return only response text bound to the configured role/model identity."""

        binding = self.gateway.binding_for(role)
        response = self.gateway.complete(role, messages)
        if response.role is not role:
            raise GatewayConfigurationError(
                f"{role.value} response returned the wrong model role"
            )
        if type(response.model_id) is not str or response.model_id != binding.model_id:
            raise GatewayConfigurationError(
                f"{role.value} response returned the wrong model identity"
            )
        if type(response.content) is not str or not response.content.strip():
            raise ValueError(f"{role.value} response content must be a non-empty string")
        return response.content

    def review(self, labrun_result: dict) -> ReviewResult:
        # Single-lane runs carry "target"; planner-driven runs carry "targets".
        target_label = (labrun_result.get("target")
                        or ", ".join(labrun_result.get("targets", [])))
        reviewed: list[ReviewedFinding] = []
        for finding in labrun_result.get("findings", []):
            payload = json.dumps(
                {"finding": finding["finding"], "severity": finding["severity"],
                 "impact": finding["impact"],
                 "target": finding.get("target", target_label),
                 "evidence_id": labrun_result.get("evidence_id", "")},
                sort_keys=True,
            )
            verdict = self._complete_text(
                ModelRole.VERIFIER,
                (ModelMessage("system", _VERIFIER_SYSTEM), ModelMessage("user", payload)),
            )
            advice = self._complete_text(
                ModelRole.REMEDIATION_ADVISOR,
                (ModelMessage("system", _REMEDIATION_SYSTEM),
                 ModelMessage("user", json.dumps(
                     {"finding": finding["finding"], "current_fix": finding["fix"]},
                     sort_keys=True))),
            )
            reviewed.append(ReviewedFinding(
                title=finding["finding"], severity=finding["severity"],
                verdict=verdict, remediation_advice=advice,
            ))

        coverage_note = json.dumps(labrun_result.get("coverage", {}).get("counts", {}))
        report = self._complete_text(
            ModelRole.REPORT_SYNTHESIZER,
            (ModelMessage("system", _REPORT_SYSTEM),
             ModelMessage("user", json.dumps(
                 {"target": target_label,
                  "findings": [f.title for f in reviewed],
                  "coverage_counts": coverage_note}, sort_keys=True))),
        )

        bindings = tuple(
            (binding.role.value, f"{binding.provider_id}/{binding.model_id}")
            for binding in (self.gateway.binding_for(role) for role in self.ROLES)
        )
        return ReviewResult(tuple(reviewed), report, bindings)
