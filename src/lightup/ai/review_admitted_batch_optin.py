"""Opt-in compatibility adapter: admit a whole batch before model dispatch.

This adapter does not alter the default AssessmentReviewPipeline, bind models,
validate grant/tenant scope, or contact a target. The caller must explicitly
opt in with an already-authorized assessment result and a configured pipeline.
The only side effect after successful admission is the pipeline's existing
model completion sequence, whose provider could be remote if so configured.
"""
from __future__ import annotations

from .pipeline import AssessmentReviewPipeline, ReviewResult
from .remediation_input_preflight_optin import prepare_remediation_review_inputs


def review_admitted_remediation_batch(
    pipeline: AssessmentReviewPipeline,
    labrun_result: object,
) -> ReviewResult:
    """Review an immutable evidence-metadata snapshot, never caller containers.

    Validate ALL findings first (including those after the first), before
    invoking the verifier. Then build fresh JSON-like containers exclusively
    from accepted immutable primitives. Raw evidence bytes, unrecognized
    caller fields and optional unvalidated coverage never cross this adapter.
    """
    if type(pipeline) is not AssessmentReviewPipeline:
        raise ValueError("review input requires an exact review pipeline")

    accepted = prepare_remediation_review_inputs(labrun_result)
    safe_findings = [
        {
            "finding": finding.title,
            "severity": finding.severity,
            "impact": finding.impact,
            "target": finding.target,
            "fix": finding.current_fix,
            "evidence_ids": list(finding.evidence_ids),
            "evidence_summary": finding.evidence_summary,
        }
        for finding in accepted.findings
    ]

    if len(accepted.findings) == 1:
        display_target = accepted.findings[0].target
    elif len(accepted.findings) > 1:
        # Never present the first target as if it represented the full batch.
        display_target = "Multiple preflighted target labels"
    else:
        display_target = "No reviewed findings"

    return pipeline.review({
        "target": display_target,
        "findings": safe_findings,
        # A coverage claim must come from its separately validated producer.
        "coverage": {"counts": {}},
    })
