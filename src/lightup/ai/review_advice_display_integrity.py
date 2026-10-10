"""Opt-in display-integrity boundary for offline remediation-advisor text.

Stacks on the W5 full-batch and advisor identity guards. This is NOT the
canonical review entrypoint or an approval, verification or retest mechanism.
Only inert synthetic fixtures should be passed to this reference path.
"""
from __future__ import annotations

import unicodedata

from .gateway import ModelGateway, ModelMessage, ModelResponse, ModelRole, RoleBinding
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
        if type(gateway) is not ModelGateway:
            raise ValueError("canonical review model gateway required")
        self._delegate = _AdvisoryResponseGuard(gateway)
        self._gateway = gateway
        self._pinned_providers: dict[str, object] = {}
        # A model/provider must not silently rebind a later role during the
        # verifier -> advisor -> report sequence. Freeze all three identities
        # before the *first* provider call; recheck before and after dispatch.
        self._pinned: dict[ModelRole, RoleBinding] = {}
        for role in AssessmentReviewPipeline.ROLES:
            binding = self._delegate.binding_for(role)
            if (
                type(binding) is not RoleBinding
                or binding.role is not role
                or type(binding.model_id) is not str
                or not binding.model_id
                or type(binding.provider_id) is not str
                or not binding.provider_id
            ):
                raise ValueError("review role binding is invalid")
            provider = gateway._providers.get(binding.provider_id)
            if provider is None:
                raise ValueError("review registered provider is invalid")
            self._pinned_providers[binding.provider_id] = provider
            self._pinned[role] = binding

    def binding_for(self, role: ModelRole):
        if role not in self._pinned:
            raise ValueError("review role binding is invalid")
        current = self._delegate.binding_for(role)
        pinned = self._pinned[role]
        if (
            type(current) is not RoleBinding
            or current.role is not role
            or type(current.provider_id) is not str
            or type(current.model_id) is not str
            or current.provider_id != pinned.provider_id
            or current.model_id != pinned.model_id
        ):
            raise ValueError("review role binding changed during batch")
        # A mutable registration map cannot replace the real provider under
        # an unchanged provider_id after this review has already begun.
        # This is identity consistency, not trusted provider attestation.
        if (
            self._gateway._providers.get(pinned.provider_id)
            is not self._pinned_providers[pinned.provider_id]
        ):
            raise ValueError("review provider instance changed during batch")
        return pinned

    def complete(
        self,
        role: ModelRole,
        messages: tuple[ModelMessage, ...],
        max_output_tokens: int = 2048,
        metadata: tuple[tuple[str, str], ...] = (),
    ) -> ModelResponse:
        binding_before = self.binding_for(role)
        response = self._delegate.complete(
            role, messages, max_output_tokens=max_output_tokens, metadata=metadata
        )
        binding_after = self.binding_for(role)
        if binding_after is not binding_before:
            raise ValueError("review role binding changed during batch")
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
            # Model-supplied usage metadata is untrusted. A negative, boolean,
            # polymorphic, or arbitrarily large count must not be treated as
            # canonical metering or flow into any future evidence receipt.
            or type(response.input_tokens) is not int
            or not 0 <= response.input_tokens <= 1_000_000
            or type(response.output_tokens) is not int
            or not 0 <= response.output_tokens <= 1_000_000
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
