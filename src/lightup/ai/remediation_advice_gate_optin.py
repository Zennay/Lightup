"""Optional remediation-advice provider gate (issue #898, PLAN/LAB ONLY).

Uninstalled provider adapter: validates the response *before* the unchanged
AssessmentReviewPipeline can forward it to REPORT_SYNTHESIZER. This is a
text-integrity boundary, NOT evidence authentication, scope or authorization.
"""
from __future__ import annotations

from .gateway import ModelProvider, ModelRequest, ModelResponse, ModelRole

_MAX_ADVICE_CHARS = 8192
_MAX_ADVICE_BYTES = 16384
_DENIED = "remediation advice must be bounded non-empty text"


class CheckedRemediationAdviceProvider(ModelProvider):
    """Opt-in delegate that refuses malformed advisor output before reporting.

    Register this wrapper with a ModelGateway *instead* of the underlying
    provider. Non-advisor roles are passed through unchanged. No pipeline,
    gateway, report or default producer is monkey-patched or replaced.
    """

    def __init__(
        self, delegate: ModelProvider, *, max_advice_chars: int = _MAX_ADVICE_CHARS
    ):
        if not isinstance(delegate, ModelProvider):
            raise ValueError("remediation advice provider is required")
        if (
            type(delegate.provider_id) is not str
            or not delegate.provider_id.strip()
            or type(max_advice_chars) is not int
            or not 1 <= max_advice_chars <= _MAX_ADVICE_CHARS
        ):
            raise ValueError("invalid remediation advice gate configuration")
        self._delegate = delegate
        self._max_advice_chars = max_advice_chars

    @property
    def provider_id(self) -> str:
        return self._delegate.provider_id

    def complete(self, request: ModelRequest) -> ModelResponse:
        response = self._delegate.complete(request)
        if request.role is not ModelRole.REMEDIATION_ADVISOR:
            return response
        if type(response) is not ModelResponse:
            raise ValueError(_DENIED)
        value = response.content
        if (
            response.role is not ModelRole.REMEDIATION_ADVISOR
            or type(value) is not str
            # Reject huge text BEFORE scanning or allocating for .strip().
            or len(value) > self._max_advice_chars
            or not value.strip()
        ):
            raise ValueError(_DENIED)
        try:
            encoded_bytes = len(value.encode("utf-8"))
        except UnicodeError:
            encoded_bytes = _MAX_ADVICE_BYTES + 1
        if encoded_bytes > _MAX_ADVICE_BYTES:
            raise ValueError(_DENIED)
        return response
