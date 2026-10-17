"""Unwired, non-authorizing ToolOutput identity review for issue #1533.

This does NOT validate a grant, authorize a scan, or dispatch a handler.
It is strictly a review aid for immutable synthetic field shapes. The real
ToolOutput contract remains owned by src/lightup/ai/orchestration.py.
"""


from enum import StrEnum


class OutputIdentityReview(StrEnum):
    HOLD = "HOLD"
    REVIEW_ONLY = "REVIEW_ONLY"

    def __bool__(self) -> bool:
        # A review receipt must never accidentally serve as truthy authority.
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
    if not summary.strip() or not evidence_kind.strip():
        return OutputIdentityReview.HOLD
    return OutputIdentityReview.REVIEW_ONLY
