"""Offline, non-authorizing triage of already-selected remediation findings.

This is an independent view model. It does not read persistence, select tenants,
validate evidence provenance, verify fixes, or dispatch any assessment work.
Callers must perform authenticated tenant/engagement selection beforehand.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import unicodedata

from .domain import FindingRecord
from .models import RetestStatus, Severity

MAX_FINDINGS = 128
MAX_EVIDENCE_IDS = 64
MAX_TEXT = 8192
MAX_ID = 128

_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}
_STAGE_RANK = {
    "collect_evidence": 0,
    "author_remediation": 1,
    "investigate_regression": 2,
    "independent_retest": 3,
    "review_remediation": 4,
}


@dataclass(frozen=True)
class RemediationReviewItem:
    """Pseudonymous review hint, not a claim about verification or consent."""

    finding_key_sha256: str
    severity: Severity
    claimed_retest_status: RetestStatus
    next_review_step: str
    referenced_evidence_count: int
    evidence_verified: bool = False
    fix_verified: bool = False
    remediation_authorized: bool = False


@dataclass(frozen=True)
class RemediationReviewQueue:
    items: tuple[RemediationReviewItem, ...]
    digest_sha256: str
    authorization_verified: bool = False
    evidence_verified: bool = False
    remediation_authorized: bool = False
    retest_authorized: bool = False
    release_authorized: bool = False

    def to_json(self) -> str:
        """Deterministic privacy-minimal advisory; never embeds source text."""
        return json.dumps({
            "schema_version": "lightup.remediation_review_queue.v3",
            "items": [
                {
                    "finding_key_sha256": item.finding_key_sha256,
                    "severity": item.severity.value,
                    "claimed_retest_status": item.claimed_retest_status.value,
                    "next_review_step": item.next_review_step,
                    "referenced_evidence_count": item.referenced_evidence_count,
                    "evidence_verified": False,
                    "fix_verified": False,
                    "remediation_authorized": False,
                }
                for item in self.items
            ],
            "digest_sha256": self.digest_sha256,
            "authorization_verified": False,
            "evidence_verified": False,
            "remediation_authorized": False,
            "retest_authorized": False,
            "release_authorized": False,
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _identity(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= MAX_ID:
        raise ValueError("invalid remediation review identity")
    if value != value.strip() or not value.isascii() or not value.isprintable():
        raise ValueError("invalid remediation review identity")
    return value


def _source_text(value: object) -> str:
    if type(value) is not str or len(value) > MAX_TEXT:
        raise ValueError("invalid remediation review source field")
    return value


def _evidence(value: object) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > MAX_EVIDENCE_IDS:
        raise ValueError("invalid remediation review evidence references")
    seen: set[str] = set()
    for ref in value:
        _identity(ref)
        if ref in seen:
            raise ValueError("invalid remediation review evidence references")
        seen.add(ref)
    return value


def _has_remediation_text(value: str) -> bool:
    """Require at least one visible letter/number, not just format controls.

    This is a *text-presence* hint, not evidence that a fix is correct or
    human-approved. Supports non-Latin letters while ignoring invisible
    format characters, isolated marks, punctuation and emoji-only strings.
    """
    return any(unicodedata.category(char)[0] in {"L", "N"} for char in value)


def _step(finding: FindingRecord) -> str:
    if not finding.evidence_ids:
        return "collect_evidence"
    if not _has_remediation_text(finding.remediation):
        return "author_remediation"
    if finding.retest_status is RetestStatus.REGRESSION:
        return "investigate_regression"
    if finding.retest_status is RetestStatus.FIXED:
        return "independent_retest"
    return "review_remediation"


def build_remediation_review_queue(
    findings: tuple[FindingRecord, ...],
    *,
    client_id: str,
    engagement_id: str,
) -> RemediationReviewQueue:
    """Create deterministic, bounded review hints with no trusted authority.

    An explicit scope match is a data consistency check, NOT authentication or
    permission. Input findings must already have been selected by a trusted
    tenant-aware caller. A reported FIXED status never becomes verified.
    """
    client_id = _identity(client_id)
    engagement_id = _identity(engagement_id)
    if type(findings) is not tuple or len(findings) > MAX_FINDINGS:
        raise ValueError("invalid remediation review findings")

    seen: set[str] = set()
    items: list[RemediationReviewItem] = []
    source_fingerprints: dict[str, str] = {}
    for finding in findings:
        if type(finding) is not FindingRecord:
            raise ValueError("invalid remediation review finding type")
        finding_id = _identity(finding.finding_id)
        if finding_id in seen:
            raise ValueError("duplicate remediation review finding")
        seen.add(finding_id)
        if _identity(finding.client_id) != client_id or (
            _identity(finding.engagement_id) != engagement_id
        ):
            raise ValueError("remediation review finding scope mismatch")
        if type(finding.severity) is not Severity or (
            type(finding.retest_status) is not RetestStatus
        ):
            raise ValueError("invalid remediation review status")
        _source_text(finding.title)
        _source_text(finding.asset)
        _source_text(finding.impact)
        _source_text(finding.remediation)
        _source_text(finding.created_at)
        references = _evidence(finding.evidence_ids)

        # This key permits deterministic correlation within an authorized
        # application context. It is NOT anonymization or an evidence digest.
        # A textual "\\0" separator is legal inside printable IDs, so
        # concatenating them permits cross-scope key aliasing. Encode each
        # identity as its own JSON tuple element instead.
        key = sha256(json.dumps(
            ("lightup-review-finding-key.v3", client_id, engagement_id, finding_id),
            separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")).hexdigest()
        # Bind the advisory digest to the *actual ordered evidence identities*
        # and full source record, not only the evidence count / display step.
        # This is change detection only: hashes never prove evidence truth,
        # data origin, authorization or independent retest verification.
        source_fingerprints[key] = sha256(json.dumps(
            (
                finding_id, finding.title, finding.asset, finding.impact,
                finding.remediation, finding.created_at,
                finding.severity.value, finding.retest_status.value,
                references,
            ),
            separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")).hexdigest()
        items.append(RemediationReviewItem(
            finding_key_sha256=key,
            severity=finding.severity,
            claimed_retest_status=finding.retest_status,
            next_review_step=_step(finding),
            referenced_evidence_count=len(references),
        ))

    ordered = tuple(sorted(items, key=lambda item: (
        _SEVERITY_RANK[item.severity],
        _STAGE_RANK[item.next_review_step],
        item.finding_key_sha256,
    )))
    canonical = [
        (
            item.finding_key_sha256,
            item.severity.value,
            item.claimed_retest_status.value,
            item.next_review_step,
            item.referenced_evidence_count,
            source_fingerprints[item.finding_key_sha256],
        )
        for item in ordered
    ]
    # Even an empty queue must be scoped: its digest must not be reusable
    # across clients / engagements with different trusted selectors.
    digest = sha256(json.dumps(
        {
            "schema_version": "lightup.remediation_review_queue.v3",
            "client_id": client_id,
            "engagement_id": engagement_id,
            "records": canonical,
        },
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()
    return RemediationReviewQueue(items=ordered, digest_sha256=digest)
