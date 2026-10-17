"""Unwired, non-authorizing ToolOutput identity review for issue #1533.

This does NOT validate a grant, authorize a scan, or dispatch a handler.
It is strictly a review aid for immutable synthetic field shapes. The real
ToolOutput contract remains owned by src/lightup/ai/orchestration.py.
"""


from enum import Enum


class OutputIdentityReview(Enum):
    HOLD = "HOLD"
    REVIEW_ONLY = "REVIEW_ONLY"

    def __bool__(self) -> bool:
        # A review receipt must never accidentally serve as truthy authority.
        return False

    @property
    def authorized(self) -> bool:
        return False

    @property
    def consent_verified(self) -> bool:
        return False

    @property
    def dispatch_allowed(self) -> bool:
        return False

    @property
    def release_allowed(self) -> bool:
        return False


def review_output_identity(summary: object, evidence_kind: object, evidence_payload: object) -> OutputIdentityReview:
    """Return REVIEW_ONLY for well-shaped plain builtins; otherwise HOLD.

    Avoid coercing or introspecting foreign objects. REVIEW_ONLY never implies
    authenticity, provenance, permission, client/operator consent or release.
    Metadata is intentionally out of scope (#1152).
    """
    if type(summary) is not str or type(evidence_kind) is not str:
        return OutputIdentityReview.HOLD
    if type(evidence_payload) is not bytes:
        return OutputIdentityReview.HOLD
    # Advisory budgets only; no producer mutation or actual evidence processing.
    # Constant-time length checks reject huge synthetic inputs without copying.
    if len(summary) > 16_384 or len(evidence_kind) > 80 or len(evidence_payload) > 4_194_304:
        return OutputIdentityReview.HOLD
    if not summary.strip() or not evidence_kind:
        return OutputIdentityReview.HOLD
    # Evidence kind is an identifier, not an arbitrary display string.
    # Reject Unicode confusables, control characters and delimiter injection.
    if not ("a" <= evidence_kind[0] <= "z"):
        return OutputIdentityReview.HOLD
    if any(not ("a" <= c <= "z" or "0" <= c <= "9" or c in "._-") for c in evidence_kind[1:]):
        return OutputIdentityReview.HOLD
    return OutputIdentityReview.REVIEW_ONLY
