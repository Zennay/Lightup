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
    "You are the remediation advisor. Improve the proposed fix using the "
    "finding's verified evidence context: concrete steps, order of operations, "
    "and how to verify the fix afterwards. Treat UNCERTAIN or REJECTED verifier "
    "decisions as evidence-status context; do not present them as confirmed."
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
_MAX_EVIDENCE_REF_CHARS = 256
_MAX_REVIEW_FINDINGS = 64
_MAX_FINDING_TEXT_CHARS = 4096
_MAX_SEVERITY_TEXT_CHARS = 64
_MAX_CURRENT_FIX_CHARS = 8192
_MAX_ADVICE_CHARS = 8192
_MAX_ADVICE_UTF8_BYTES = 16384


def _validated_remediation_advice(content: str) -> str:
    """Deny unusable advice before it becomes a finding or report input."""
    if type(content) is not str or not content.strip():
        raise ValueError("remediation-advisor output must be non-empty plain text")
    if len(content) > _MAX_ADVICE_CHARS:
        raise ValueError("remediation-advisor output exceeds the display ceiling")
    try:
        encoded = content.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("remediation-advisor output must be valid UTF-8") from exc
    if len(encoded) > _MAX_ADVICE_UTF8_BYTES:
        raise ValueError("remediation-advisor output exceeds the byte ceiling")
    return content




def _admit_review_findings(labrun_result: dict, target_label: str) -> tuple[tuple[dict, str, tuple[str, ...], str, str], ...]:
    """Validate EVERY original finding before the first model dispatch.

    A later broken case must not allow earlier cases to issue model requests.
    Preserve legitimate leading/trailing fix spaces and original evidence order.
    """
    if type(labrun_result) is not dict:
        raise ValueError("review input must be an ordinary dictionary")
    originals = labrun_result.get("findings", [])
    if type(originals) is not list or len(originals) > _MAX_REVIEW_FINDINGS:
        raise ValueError("review findings must be a bounded JSON list")
    batch: list[tuple[dict, str, tuple[str, ...], str, str]] = []
    seen_finding_ids: set[str] = set()
    for finding in originals:
        if type(finding) is not dict:
            raise ValueError("review finding must be an ordinary dictionary")
        for label, maximum in (
            ("finding", _MAX_FINDING_TEXT_CHARS),
            ("severity", _MAX_SEVERITY_TEXT_CHARS),
            ("impact", _MAX_FINDING_TEXT_CHARS),
        ):
            value = finding.get(label)
            if type(value) is not str or not value.strip() or len(value) > maximum:
                raise ValueError(f"review finding requires bounded {label} text")
        summary = finding.get("evidence_summary")
        declared = finding.get("evidence_ids")
        if declared is None:
            source_id = labrun_result.get("evidence_id")
            refs = (source_id,) if source_id else ()
        else:
            if type(declared) is not list:
                raise ValueError("review finding evidence references must be a JSON list")
            refs = tuple(declared)
        if (type(summary) is not str or not summary.strip()
                or len(summary) > _MAX_EVIDENCE_SUMMARY_CHARS):
            raise ValueError("review findings require bounded non-empty evidence summary")
        if (not refs or len(refs) > _MAX_EVIDENCE_REFS
                or any(type(ref) is not str or not ref.strip()
                       or len(ref) > _MAX_EVIDENCE_REF_CHARS for ref in refs)
                or len(set(refs)) != len(refs)):
            raise ValueError("review findings require distinct bounded evidence references")
        fix = finding.get("fix")
        if (type(fix) is not str or not fix.strip()
                or len(fix) > _MAX_CURRENT_FIX_CHARS):
            raise ValueError("review findings require canonical non-empty current remediation text")
        finding_target = finding.get("target", target_label)
        if (type(finding_target) is not str or not finding_target.strip()
                or len(finding_target) > _MAX_FINDING_TEXT_CHARS):
            raise ValueError("review finding target must be bounded plain text")
        # The source producer's ID is kept exact for report/triage correlation.
        # Existing independent consumers may omit it; no ID is fabricated.
        finding_id = finding.get("finding_id")
        if finding_id is not None and (
                type(finding_id) is not str or not finding_id.strip()
                or len(finding_id) > 256
                or any(ord(ch) < 33 or ord(ch) > 126 for ch in finding_id)
        ):
            raise ValueError("review finding requires a canonical finding identity")
        if finding_id is not None:
            if finding_id in seen_finding_ids:
                raise ValueError("review findings require distinct finding identities")
            seen_finding_ids.add(finding_id)
        # Freeze the same finding-local target used by verification, advice,
        # serialized review and reporting before ANY model call.
        batch.append((dict(finding), summary, refs, fix, finding_target))
    return tuple(batch)




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
    target: str = ""
    finding_id: str | None = None


@dataclass(frozen=True)
class ReviewResult:
    findings: tuple[ReviewedFinding, ...]
    report: str
    model_bindings: tuple[tuple[str, str], ...]

    def to_dict(self) -> dict:
        return {
            "findings": [
                {**{"finding": f.title, "severity": f.severity, "verdict": f.verdict,
                    "remediation_advice": f.remediation_advice, "target": f.target},
                 **({"finding_id": f.finding_id} if f.finding_id is not None else {})}
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
        # Complete original source preflight before *any* gateway dispatch.
        if type(labrun_result) is not dict:
            raise ValueError("review input must be an ordinary dictionary")
        # Single-lane runs carry "target"; planner-driven runs carry "targets".
        # Preserve the original single-target or planner-list fallback without
        # accepting malformed iterable or caller-defined string subclasses.
        run_target = labrun_result.get("target")
        run_targets = labrun_result.get("targets", [])
        if run_target:
            if type(run_target) is not str or len(run_target) > _MAX_FINDING_TEXT_CHARS:
                raise ValueError("review run target must be bounded plain text")
            target_label = run_target
        else:
            if (type(run_targets) is not list or len(run_targets) > _MAX_REVIEW_FINDINGS
                    or any(type(value) is not str
                           or len(value) > _MAX_FINDING_TEXT_CHARS for value in run_targets)):
                raise ValueError("review run targets must be bounded plain-text strings")
            target_label = ", ".join(run_targets)
            if len(target_label) > _MAX_FINDING_TEXT_CHARS:
                raise ValueError("review run target label is too long")
        admitted = _admit_review_findings(labrun_result, target_label)
        reviewed: list[ReviewedFinding] = []
        for finding, evidence_summary, evidence_ids, current_fix, finding_target in admitted:
            payload = json.dumps(
                {"finding": finding["finding"], "severity": finding["severity"],
                 "impact": finding["impact"],
                 "target": finding_target,
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
                     {
                         "finding": finding["finding"],
                         "severity": finding["severity"],
                         "impact": finding["impact"],
                         "target": finding_target,
                         "current_fix": current_fix,
                         "verifier_verdict": verdict,
                         "evidence_ids": evidence_ids,
                         "evidence_summary": evidence_summary,
                     },
                     sort_keys=True))),
            ).content
            advice = _validated_remediation_advice(advice)
            reviewed.append(ReviewedFinding(
                title=finding["finding"], severity=finding["severity"],
                verdict=verdict, remediation_advice=advice, target=finding_target,
                finding_id=finding.get("finding_id"),
            ))

        coverage_counts = labrun_result.get("coverage", {}).get("counts", {})
        report_findings = [
            {
                **{
                    "finding": finding.title,
                    "severity": finding.severity,
                    "verdict": finding.verdict,
                    "remediation_advice": finding.remediation_advice,
                    "target": finding.target,
                },
                **({"finding_id": finding.finding_id}
                   if finding.finding_id is not None else {}),
            }
            for finding in reviewed
        ]
        report = self.gateway.complete(
            ModelRole.REPORT_SYNTHESIZER,
            (ModelMessage("system", _REPORT_SYSTEM),
             ModelMessage("user", json.dumps(
                 {"target": target_label,
                  "findings": report_findings,
                  "coverage_counts": coverage_counts}, sort_keys=True))),
        ).content

        bindings = tuple(
            (binding.role.value, f"{binding.provider_id}/{binding.model_id}")
            for binding in (self.gateway.binding_for(role) for role in self.ROLES)
        )
        return ReviewResult(tuple(reviewed), report, bindings)
