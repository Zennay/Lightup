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

from .gateway import ModelGateway, ModelMessage, ModelRole

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
_VERDICT_TOKENS = ("CONFIRMED", "UNCERTAIN", "REJECTED")
_MAX_EVIDENCE_SUMMARY_CHARS = 4096
_MAX_EVIDENCE_REFS = 64


def _validated_verifier_verdict(value: str) -> str:
    """Require the verifier's declared decision before remediation is derived."""

    first_line = value.split("\n", 1)[0]
    if not any(
        first_line == token or first_line.startswith(f"{token} ")
        for token in _VERDICT_TOKENS
    ):
        raise ValueError(
            "verifier verdict must start with CONFIRMED, UNCERTAIN or REJECTED"
        )
    return value


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

    def review(self, labrun_result: dict) -> ReviewResult:
        # Single-lane runs carry "target"; planner-driven runs carry "targets".
        target_label = (labrun_result.get("target")
                        or ", ".join(labrun_result.get("targets", [])))
        reviewed: list[ReviewedFinding] = []
        for finding in labrun_result.get("findings", []):
            evidence_summary = finding.get("evidence_summary")
            evidence_ids = tuple(finding.get("evidence_ids", ()))
            if not evidence_ids:
                top_level_evidence_id = labrun_result.get("evidence_id")
                if top_level_evidence_id:
                    evidence_ids = (top_level_evidence_id,)
            if (
                type(evidence_summary) is not str
                or not evidence_summary.strip()
                or len(evidence_summary) > _MAX_EVIDENCE_SUMMARY_CHARS
            ):
                raise ValueError(
                    "review findings require a bounded non-empty evidence summary"
                )
            if (
                not evidence_ids
                or len(evidence_ids) > _MAX_EVIDENCE_REFS
                or any(type(evidence_id) is not str or not evidence_id.strip()
                       for evidence_id in evidence_ids)
            ):
                raise ValueError(
                    "review findings require bounded non-empty evidence references"
                )
            payload = json.dumps(
                {"finding": finding["finding"], "severity": finding["severity"],
                 "impact": finding["impact"],
                 "target": finding.get("target", target_label),
                 "evidence_ids": evidence_ids,
                 "evidence_summary": evidence_summary},
                sort_keys=True,
            )
            verdict = _validated_verifier_verdict(
                self.gateway.complete(
                    ModelRole.VERIFIER,
                    (ModelMessage("system", _VERIFIER_SYSTEM), ModelMessage("user", payload)),
                ).content
            )
            advice = self.gateway.complete(
                ModelRole.REMEDIATION_ADVISOR,
                (ModelMessage("system", _REMEDIATION_SYSTEM),
                 ModelMessage("user", json.dumps(
                     {"finding": finding["finding"], "current_fix": finding["fix"]},
                     sort_keys=True))),
            ).content
            reviewed.append(ReviewedFinding(
                title=finding["finding"], severity=finding["severity"],
                verdict=verdict, remediation_advice=advice,
            ))

        coverage_note = json.dumps(labrun_result.get("coverage", {}).get("counts", {}))
        report = self.gateway.complete(
            ModelRole.REPORT_SYNTHESIZER,
            (ModelMessage("system", _REPORT_SYSTEM),
             ModelMessage("user", json.dumps(
                 {"target": target_label,
                  "findings": [f.title for f in reviewed],
                  "coverage_counts": coverage_note}, sort_keys=True))),
        ).content

        bindings = tuple(
            (binding.role.value, f"{binding.provider_id}/{binding.model_id}")
            for binding in (self.gateway.binding_for(role) for role in self.ROLES)
        )
        return ReviewResult(tuple(reviewed), report, bindings)
