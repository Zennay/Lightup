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
REVIEW_QUEUE_SCHEMA_VERSION = "lightup.remediation_review_queue.v4"

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

_HEX = frozenset("0123456789abcdef")


def _digest_shaped(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(c in _HEX for c in value)


@dataclass(frozen=True)
class RemediationReviewItem:
    """Pseudonymous review hint, not a claim about verification or consent."""

    finding_key_sha256: str
    severity: Severity
    claimed_retest_status: RetestStatus
    next_review_step: str
    referenced_evidence_count: int
    review_actions: tuple[str, ...]
    evidence_verified: bool = False
    fix_verified: bool = False
    remediation_authorized: bool = False

    def __post_init__(self) -> None:
        # In-memory review models must not be directly constructed as positive
        # evidence/authorization objects, even if the caller skips our builder.
        if any(value is not False for value in (
            self.evidence_verified, self.fix_verified, self.remediation_authorized,
        )):
            raise ValueError("review advisory cannot certify evidence, fix or execution")
        if (
            not _digest_shaped(self.finding_key_sha256)
            or type(self.severity) is not Severity
            or type(self.claimed_retest_status) is not RetestStatus
            or type(self.next_review_step) is not str
            or self.next_review_step not in _STAGE_RANK
            or type(self.referenced_evidence_count) is not int
            or not 0 <= self.referenced_evidence_count <= MAX_EVIDENCE_IDS
            or type(self.review_actions) is not tuple
            or not 1 <= len(self.review_actions) <= 4
            or any(type(action) is not str or action not in _STAGE_RANK
                   for action in self.review_actions)
            or len(set(self.review_actions)) != len(self.review_actions)
            or tuple(sorted(self.review_actions, key=_STAGE_RANK.__getitem__))
               != self.review_actions
            or self.next_review_step != self.review_actions[0]
            or ("review_remediation" in self.review_actions
                and len(self.review_actions) != 1)
        ):
            raise ValueError("invalid remediation review advisory item")
        # Additional obligations derived from fields that are present in the
        # item itself cannot be omitted or forged by a direct constructor.
        # Missing remediation text is not stored here for privacy, so its
        # authoring obligation still depends on the trusted builder.
        actions = self.review_actions
        evidence_missing = self.referenced_evidence_count == 0
        fixed_claim = self.claimed_retest_status is RetestStatus.FIXED
        regression_claim = self.claimed_retest_status is RetestStatus.REGRESSION
        if (
            ("collect_evidence" in actions) != evidence_missing
            or ("independent_retest" in actions) != fixed_claim
            or ("investigate_regression" in actions) != regression_claim
        ):
            raise ValueError("inconsistent remediation review advisory obligations")


@dataclass(frozen=True)
class RemediationReviewQueue:
    items: tuple[RemediationReviewItem, ...]
    digest_sha256: str
    authorization_verified: bool = False
    evidence_verified: bool = False
    remediation_authorized: bool = False
    retest_authorized: bool = False
    release_authorized: bool = False

    def __post_init__(self) -> None:
        # A frozen dataclass is a view model, NOT a security trust boundary.
        # Reject ordinary direct-construction attempts to set any positive
        # authority flag or insert arbitrary forged review steps.
        if any(value is not False for value in (
            self.authorization_verified, self.evidence_verified,
            self.remediation_authorized, self.retest_authorized,
            self.release_authorized,
        )):
            raise ValueError("review advisory cannot certify authorization or release")
        if (
            type(self.items) is not tuple or len(self.items) > MAX_FINDINGS
            or any(type(item) is not RemediationReviewItem for item in self.items)
            or not _digest_shaped(self.digest_sha256)
            or len({item.finding_key_sha256 for item in self.items}) != len(self.items)
        ):
            raise ValueError("invalid remediation review advisory queue")
        if any(
            item.evidence_verified is not False
            or item.fix_verified is not False
            or item.remediation_authorized is not False
            for item in self.items
        ):
            raise ValueError("review advisory cannot certify item evidence or fix")

    @property
    def review_action_counts(self) -> tuple[tuple[str, int], ...]:
        """Pure tenant-scoped workload counts, never progress certification.

        A single finding may contribute to more than one count because it can
        need evidence, remediation authoring and an independent retest. Return
        an immutable ordered tuple so no mutable accumulator escapes.
        """
        totals = {action: 0 for action in _STAGE_RANK}
        for item in self.items:
            for action in item.review_actions:
                totals[action] += 1
        return tuple((action, count) for action, count in totals.items() if count)

    def items_needing_review_action(
        self, action: str,
    ) -> tuple[RemediationReviewItem, ...]:
        """Filter advisory items by one human task; never dispatch work.

        Includes secondary obligations rather than filtering solely on the
        item's primary next_review_step. No external services or DB are
        consulted; the result retains the original severity-first order.
        """
        if type(action) is not str or action not in _STAGE_RANK:
            raise ValueError("invalid remediation human-review action selector")
        return tuple(item for item in self.items if action in item.review_actions)

    def to_json(self) -> str:
        """Deterministic privacy-minimal advisory; never embeds source text."""
        return json.dumps({
            "schema_version": REVIEW_QUEUE_SCHEMA_VERSION,
            "items": [
                {
                    "finding_key_sha256": item.finding_key_sha256,
                    "severity": item.severity.value,
                    "claimed_retest_status": item.claimed_retest_status.value,
                    "next_review_step": item.next_review_step,
                    "review_actions": list(item.review_actions),
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


def _review_actions(finding: FindingRecord) -> tuple[str, ...]:
    """Preserve independent human review needs, never execution permission.

    Multiple blockers must not disappear merely because the primary sorting
    step reports the first one. No evidence/retest/remediation verification
    is inferred from an action's presence or absence.
    """
    actions: list[str] = []
    if not finding.evidence_ids:
        actions.append("collect_evidence")
    if not _has_remediation_text(finding.remediation):
        actions.append("author_remediation")
    if finding.retest_status is RetestStatus.REGRESSION:
        actions.append("investigate_regression")
    if finding.retest_status is RetestStatus.FIXED:
        actions.append("independent_retest")
    if not actions:
        actions.append("review_remediation")
    return tuple(actions)


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
        review_actions = _review_actions(finding)
        items.append(RemediationReviewItem(
            finding_key_sha256=key,
            severity=finding.severity,
            claimed_retest_status=finding.retest_status,
            next_review_step=review_actions[0],
            review_actions=review_actions,
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
            item.review_actions,
            item.referenced_evidence_count,
            source_fingerprints[item.finding_key_sha256],
        )
        for item in ordered
    ]
    # Even an empty queue must be scoped: its digest must not be reusable
    # across clients / engagements with different trusted selectors.
    digest = sha256(json.dumps(
        {
            "schema_version": REVIEW_QUEUE_SCHEMA_VERSION,
            "client_id": client_id,
            "engagement_id": engagement_id,
            "records": canonical,
        },
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()
    return RemediationReviewQueue(items=ordered, digest_sha256=digest)
