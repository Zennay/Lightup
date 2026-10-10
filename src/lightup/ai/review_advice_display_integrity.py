"""Opt-in display-integrity boundary for offline remediation-advisor text.

Stacks on the W5 full-batch and advisor identity guards. This is NOT the
canonical review entrypoint or an approval, verification or retest mechanism.
Only inert synthetic fixtures should be passed to this reference path.
"""
from __future__ import annotations

import unicodedata

from .gateway import ModelGateway, ModelMessage, ModelResponse, ModelRole, RoleBinding
from .pipeline import AssessmentReviewPipeline, ReviewResult
from ..models import Severity
from .review_advice_guard import _AdvisoryResponseGuard
from .review_batch_preflight import preflight_review_batch

_MAX_TEXT_CHARS = 8192
_MAX_TEXT_BYTES = 16384
_MAX_TOTAL_VERIFIER_BYTES = 32768
_MAX_TOTAL_ADVISOR_BYTES = 32768
_MAX_TOTAL_INPUT_BYTES = 262144
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


class _SanitizedProviderGateway:
    """Keep upstream provider and gateway error text out of public responses.

    This does not make provider calls side-effect-free. The caller must still
    authorize any external provider disclosure before entering this adapter.
    """

    def __init__(self, original: ModelGateway):
        self._original = original

    def binding_for(self, role: ModelRole):
        return self._original.binding_for(role)

    def complete(
        self,
        role: ModelRole,
        messages: tuple[ModelMessage, ...],
        max_output_tokens: int = 2048,
        metadata: tuple[tuple[str, str], ...] = (),
    ) -> ModelResponse:
        try:
            return self._original.complete(
                role, messages, max_output_tokens=max_output_tokens, metadata=metadata
            )
        except Exception:
            # No model/vendor error text, prompt, credentials or evidence bytes
            # may become a user-facing exception through the opt-in pipeline.
            raise ValueError("review model provider failed") from None


class _DisplaySafeAdviceGateway:
    """Stack display checks after W5 response identity checks, before report."""

    def __init__(self, gateway: ModelGateway):
        if type(gateway) is not ModelGateway:
            raise ValueError("canonical review model gateway required")
        # The existing W5 advisor-shape guard remains on top of this delegate.
        # Its own deterministic validation messages are not rewritten.
        self._delegate = _AdvisoryResponseGuard(_SanitizedProviderGateway(gateway))
        self._gateway = gateway
        self._pinned_providers: dict[str, object] = {}
        self._total_verifier_bytes = 0
        self._total_advisor_bytes = 0
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
        if role is ModelRole.VERIFIER:
            checked_remediation_display_text(response.content)
            # The verifier's source-owned system instruction requires exactly
            # one decision line. A second line can smuggle a contradictory
            # "CONFIRMED" statement behind a first-line UNCERTAIN/REJECTED
            # decision, which then reaches the advisor and report unchanged.
            if "\n" in response.content or "\t" in response.content:
                raise ValueError("review verifier verdict must be a single line")
            # Verdicts are echoed into advisor prompts AND the final summary
            # payload. A bounded single reply is not a bounded whole batch.
            total = self._total_verifier_bytes + len(response.content.encode("utf-8"))
            if total > _MAX_TOTAL_VERIFIER_BYTES:
                raise ValueError("review verifier verdict batch limit exceeded")
            self._total_verifier_bytes = total
        if role is ModelRole.REMEDIATION_ADVISOR:
            checked_remediation_display_text(response.content)
            # Every answer may be individually bounded while the total
            # client-facing report prompt still grows across 128 findings.
            # Refuse excessive cumulative advice before report synthesis.
            next_size = self._total_advisor_bytes + len(response.content.encode("utf-8"))
            if next_size > _MAX_TOTAL_ADVISOR_BYTES:
                raise ValueError("remediation review advice batch limit exceeded")
            self._total_advisor_bytes = next_size
        elif role is ModelRole.REPORT_SYNTHESIZER:
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
    # The canonical pipeline would otherwise synthesize a client-facing
    # assessment report even with zero findings, or without a target label.
    # Do not let a well-shaped but ungrounded empty review imply that anything
    # was assessed. Reject prior to the *first* provider request.
    if not checked["findings"]:
        raise ValueError("review batch requires at least one finding")
    if checked["target"] is None and not checked["targets"]:
        raise ValueError("review batch requires explicit target context")
    # The canonical pipeline silently prefers "target" over "targets".
    # A conflicting second source would be ignored in all role prompts.
    if checked["target"] is not None and checked["targets"] not in (
        [], [checked["target"]]
    ):
        raise ValueError("review batch has conflicting target context")
    # Complete the entire input-display audit before the first model call:
    # a malformed current fix in a *later* finding must never dispatch an
    # earlier finding to any model provider. Keep the W5 detached snapshot.
    # Validate every field actually forwarded into a model prompt or returned
    # as client-facing review context. A second-row control byte must not let
    # the first row trigger a model request. Reject instead of normalizing.
    fields = [checked["target"], *checked["targets"]]
    # The default AI review path treats severity as display text. For this
    # opt-in evidence-review contract, refuse invented or disguised severity
    # labels rather than sending them to a reviewer/report as canonical facts.
    permitted_severities = frozenset(member.value for member in Severity)
    for finding in checked["findings"]:
        if finding["severity"] not in permitted_severities:
            raise ValueError("review finding severity is not canonical")
        fields.extend(finding[name] for name in (
            "finding", "severity", "impact", "fix", "evidence_summary"
        ))
        fields.extend(finding["evidence_ids"])
        if "target" in finding:
            fields.append(finding["target"])
    fields.extend(checked["coverage"]["counts"])
    # Individually bounded strings can still sum to megabytes across a full
    # 128-finding batch. Refuse unbounded aggregate prompt construction before
    # the first provider request. This is a conservative opt-in safety cap.
    total_input_bytes = 0
    for value in fields:
        if value is not None:
            try:
                checked_remediation_display_text(value)
            except ValueError:
                raise ValueError("review input display text is invalid") from None
            total_input_bytes += len(value.encode("utf-8"))
            if total_input_bytes > _MAX_TOTAL_INPUT_BYTES:
                raise ValueError("review input batch byte limit exceeded")
    # The default pipeline accepts a finding-local target override without
    # checking whether it belongs to the declared review target set. A
    # multi-target fallback also turns an unspecified finding target into the
    # comma-joined label "A, B", which is not reliable evidence lineage.
    # Restrict this *opt-in* review to an explicit and unambiguous mapping.
    declared_targets = checked["targets"] or [checked["target"]]
    if len(set(declared_targets)) != len(declared_targets):
        raise ValueError("review batch has duplicate target context")
    for finding in checked["findings"]:
        if len(declared_targets) > 1 and "target" not in finding:
            raise ValueError("multi-target review requires finding target context")
        if "target" in finding and finding["target"] not in declared_targets:
            raise ValueError("review finding target is outside declared context")
    return AssessmentReviewPipeline(_DisplaySafeAdviceGateway(pipeline.gateway)).review(
        checked
    )
