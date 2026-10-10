"""Opt-in output-readiness guard around the real offline review pipeline.

Source owner #846 retains the default review path. A response validation
error cannot be used as an authorization grant, retest proof or verdict.
"""
from __future__ import annotations

from .gateway import ModelGateway, ModelResponse, ModelRole
from .pipeline import AssessmentReviewPipeline, ReviewResult
from .review_batch_preflight import preflight_review_batch

_MAX_ADVICE_CHARS = 8192


class _AdvisoryResponseGuard:
    """A local gateway delegate; validate the advisor reply before reporting."""

    def __init__(self, original: ModelGateway):
        self._original = original

    def binding_for(self, role: ModelRole):
        return self._original.binding_for(role)

    def complete(
        self,
        role: ModelRole,
        messages: tuple,
        max_output_tokens: int = 2048,
        metadata: tuple[tuple[str, str], ...] = (),
    ) -> ModelResponse:
        response = self._original.complete(
            role, messages, max_output_tokens=max_output_tokens, metadata=metadata
        )
        if role is ModelRole.REMEDIATION_ADVISOR:
            # Check exact reply identity and canonical text without coercion or
            # normalization. Never include provider content in exceptions.
            if (
                type(response) is not ModelResponse
                or response.role is not role
                or type(response.content) is not str
                or not response.content.strip()
                or len(response.content) > _MAX_ADVICE_CHARS
                or type(response.model_id) is not str
                or response.model_id != self.binding_for(role).model_id
            ):
                raise ValueError("remediation advisor returned invalid bounded advice")
        return response


def review_with_batch_and_advice_guards(
    pipeline: AssessmentReviewPipeline, source: object
) -> ReviewResult:
    """Optional full-batch admission + post-advisor/pre-report guard.

    This offline reference is intentionally NOT used by the production app.
    Real remote providers additionally require trusted disclosure permissions
    and authenticated tenant selection outside these input/output checks.
    """
    if type(pipeline) is not AssessmentReviewPipeline:
        raise ValueError("canonical review pipeline required")
    checked = preflight_review_batch(source)  # No provider effects before this.
    return AssessmentReviewPipeline(_AdvisoryResponseGuard(pipeline.gateway)).review(
        checked
    )
