"""Opt-in display-integrity boundary for offline remediation-advisor text.

Stacks on the W5 full-batch and advisor identity guards. This is NOT the
canonical review entrypoint or an approval, verification or retest mechanism.
Only inert synthetic fixtures should be passed to this reference path.
"""
from __future__ import annotations

import unicodedata

from .gateway import ModelGateway, ModelMessage, ModelResponse, ModelRole
from .pipeline import AssessmentReviewPipeline, ReviewResult
from .review_advice_guard import _AdvisoryResponseGuard
from .review_batch_preflight import preflight_review_batch

_MAX_TEXT_CHARS = 8192
_MAX_TEXT_BYTES = 16384
_ALLOWED_LAYOUT = frozenset(("\n", "\t"))


def checked_remediation_display_text(value: object) -> str:
    """Preserve printable advice verbatim; reject unsafe display controls.

    Reject exact-type confusion, blank, oversized, ill-formed UTF-8,
    nonprintable format/control characters (including bidi overrides and
    zero-width marks), surrogate and private/unassigned code points.
    Newlines/tabs are allowed for normal multiline advice. A positive
    result asserts only safe presentation shape, NEVER evidence truth.
    """
    if type(value) is not str or not value.strip() or len(value) > _MAX_TEXT_CHARS:
        raise ValueError("remediation advice display text is invalid")
    try:
        size = len(value.encode("utf-8", errors="strict"))
    except UnicodeError:
        raise ValueError("remediation advice display text is invalid") from None
    if size > _MAX_TEXT_BYTES:
        raise ValueError("remediation advice display text is invalid")
    for character in value:
        if character in _ALLOWED_LAYOUT:
            continue
        if unicodedata.category(character).startswith("C"):
            raise ValueError("remediation advice display text is invalid")
    return value


class _DisplaySafeAdviceGateway:
    """Stack display checks after W5 response identity checks, before report."""

    def __init__(self, gateway: ModelGateway):
        self._delegate = _AdvisoryResponseGuard(gateway)

    def binding_for(self, role: ModelRole):
        return self._delegate.binding_for(role)

    def complete(
        self,
        role: ModelRole,
        messages: tuple[ModelMessage, ...],
        max_output_tokens: int = 2048,
        metadata: tuple[tuple[str, str], ...] = (),
    ) -> ModelResponse:
        response = self._delegate.complete(
            role, messages, max_output_tokens=max_output_tokens, metadata=metadata
        )
        # The default ModelGateway verifies only provider_id. This optional
        # wrapper additionally binds *every* returned role/model to its request,
        # before a verifier verdict can influence the advisor or a report can
        # be returned to a caller. Do not trust provider-supplied role strings.
        binding = self.binding_for(role)
        if (
            type(response) is not ModelResponse
            or response.role is not role
            or type(response.model_id) is not str
            or response.model_id != binding.model_id
            or type(response.provider_id) is not str
            or response.provider_id != binding.provider_id
        ):
            raise ValueError("review model response identity is invalid")
        if role is ModelRole.REMEDIATION_ADVISOR:
            checked_remediation_display_text(response.content)
        else:
            try:
                checked_remediation_display_text(response.content)
            except ValueError:
                raise ValueError("review model response display text is invalid") from None
        return response


def review_with_display_safe_advice(
    pipeline: AssessmentReviewPipeline, source: object,
) -> ReviewResult:
    """Whole-batch admission and bounded advisor output without target I/O.

    A real caller still needs trusted tenant/session disclosure authorization,
    revocation and evidence verification. No provider, scan or tool is started
    by this helper; a caller-provided pipeline may separately bind a provider.
    """
    if type(pipeline) is not AssessmentReviewPipeline:
        raise ValueError("canonical review pipeline required")
    checked = preflight_review_batch(source)
    # Complete the entire input-display audit before the first model call:
    # a malformed current fix in a *later* finding must never dispatch an
    # earlier finding to any model provider. Keep the W5 detached snapshot.
    # Validate every field actually forwarded into a model prompt or returned
    # as client-facing review context. A second-row control byte must not let
    # the first row trigger a model request. Reject instead of normalizing.
    fields = [checked["target"], *checked["targets"]]
    for finding in checked["findings"]:
        fields.extend(finding[name] for name in (
            "finding", "severity", "impact", "fix", "evidence_summary"
        ))
        fields.extend(finding["evidence_ids"])
        if "target" in finding:
            fields.append(finding["target"])
    fields.extend(checked["coverage"]["counts"])
    for value in fields:
        if value is not None:
            try:
                checked_remediation_display_text(value)
            except ValueError:
                raise ValueError("review input display text is invalid") from None
    return AssessmentReviewPipeline(_DisplaySafeAdviceGateway(pipeline.gateway)).review(
        checked
    )
