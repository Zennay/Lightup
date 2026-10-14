"""Opt-in Unicode evidence reference admission before DomainStore.record_finding.

Non-installed M3/M7 PLAN/LAB demonstration; the canonical write/read paths,
tenant/session authentication, verifier and runtime execution remain untouched.
"""
from __future__ import annotations

import json
import unicodedata

from .domain import AccessContext, DomainStore, FindingRecord
from .models import Severity

_ERROR = "invalid finding evidence write integrity"
_MAX_REFS = 128
_MAX_REF_UTF8_BYTES = 4096
_MAX_JSON_UTF8_BYTES = 262144


def checked_written_evidence_references_w33(value: object) -> tuple[str, ...]:
    """Check provenance-free reference syntax; never normalize stored identities."""
    if type(value) is not tuple or len(value) > _MAX_REFS:
        raise ValueError(_ERROR)
    seen_compatibility: set[str] = set()
    for reference in value:
        if type(reference) is not str or not reference or reference != reference.strip():
            raise ValueError(_ERROR)
        try:
            length = len(reference.encode("utf-8", "strict"))
        except UnicodeError:
            raise ValueError(_ERROR) from None
        if length > _MAX_REF_UTF8_BYTES:
            raise ValueError(_ERROR)

        previous_base = False
        for char in reference:
            category = unicodedata.category(char)
            if category[0] == "C" or category in ("Zl", "Zp") or char == "\u034f":
                raise ValueError(_ERROR)
            if category == "Zs":
                if char != " ":
                    raise ValueError(_ERROR)
                previous_base = False
            elif category[0] == "M":
                if not previous_base:
                    raise ValueError(_ERROR)
            else:
                # A punctuation mark is not a Unicode combining base.
                # Emoji symbols, letters and numbers can anchor marks.
                previous_base = category[0] in "LNS"

        normalized = unicodedata.normalize("NFKC", reference)
        if normalized in seen_compatibility:
            raise ValueError(_ERROR)
        seen_compatibility.add(normalized)

    # Mirror the current DomainStore JSON rendering for an exact byte budget.
    # The original DB serializer uses ensure_ascii=True and default separators.
    try:
        encoded = json.dumps(list(value)).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError):
        raise ValueError(_ERROR) from None
    if len(encoded) > _MAX_JSON_UTF8_BYTES:
        raise ValueError(_ERROR)
    return value


def record_finding_checked_unicode_optin_w33(
    store: DomainStore,
    context: AccessContext,
    engagement_id: str,
    title: str,
    severity: Severity,
    asset: str,
    impact: str,
    remediation: str,
    evidence_ids: object = (),
) -> FindingRecord:
    """Apply only conservative read-compatible evidence syntax before INSERT.

    This is NOT authentication, tenant or evidence provenance verification.
    Canonical DomainStore.record_finding enforces its own roles and record
    validity; the helper never broadens permissions or changes source data.
    """
    if type(store) is not DomainStore:
        raise TypeError("canonical DomainStore required")
    checked = checked_written_evidence_references_w33(evidence_ids)
    return store.record_finding(
        context, engagement_id, title, severity, asset, impact, remediation,
        evidence_ids=checked,
    )
