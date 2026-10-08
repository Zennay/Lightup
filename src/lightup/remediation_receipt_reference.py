"""Offline evidence-to-remediation/retest receipt consistency gate.

This is a data-integrity check, not an assessment or authorization decision.
No filesystem, network, subprocess or security capabilities are used.
"""
from __future__ import annotations

import re

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_STATES = frozenset({"pending", "passed", "failed", "not_tested"})
_KEYS = frozenset({"finding_id", "evidence_sha256", "remediation_sha256", "retest_status", "retest_evidence_sha256"})


def validate_remediation_receipt(receipt: object) -> dict[str, str | None]:
    """Return an isolated canonical snapshot or fail closed on ambiguous evidence."""
    if type(receipt) is not dict or set(receipt) != _KEYS:
        raise ValueError("invalid remediation receipt schema")
    finding = receipt["finding_id"]
    if type(finding) is not str or not finding or len(finding) > 128 or finding.strip() != finding:
        raise ValueError("invalid finding identity")
    for field in ("evidence_sha256", "remediation_sha256"):
        value = receipt[field]
        if type(value) is not str or _HASH.fullmatch(value) is None:
            raise ValueError(f"invalid {field}")
    status = receipt["retest_status"]
    if type(status) is not str or status not in _STATES:
        raise ValueError("invalid retest status")
    retest = receipt["retest_evidence_sha256"]
    if status in {"passed", "failed"}:
        if type(retest) is not str or _HASH.fullmatch(retest) is None:
            raise ValueError("retest result lacks canonical evidence")
        if retest == receipt["evidence_sha256"]:
            raise ValueError("retest result reuses original evidence")
    elif retest is not None:
        raise ValueError("uncompleted retest cannot claim retest evidence")
    return {key: receipt[key] for key in sorted(_KEYS)}
