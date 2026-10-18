"""Client-side revision of a REJECTED assessment request, never an approval.

A revision is a NEW submitted request. It never edits a reviewed original,
inherits an operator decision, binds a grant, or authorizes target access.
"""
from __future__ import annotations

import hashlib
import json

from .client_request_cli import ClientRequestError, canonical_assets, prepare_request
from .domain import AssessmentRequestRecord, RequestStatus
from .engagements import AssessmentMode
from .grant_request_binding import _asset


def original_revision_sha256(record: AssessmentRequestRecord) -> str:
    """Unsigned version snapshot for an already authenticated client record."""
    data = {
        "request_id": record.request_id,
        "client_id": record.client_id,
        "requested_by": record.requested_by,
        "created_at": record.created_at,
        "requested_mode": record.requested_mode.value,
        "requested_risk": int(record.requested_risk),
        "requested_assets": list(record.requested_assets),
        "notes": record.notes,
        "status": record.status.value,
        "decided_by": record.decided_by,
        "decided_at": record.decided_at,
    }
    encoded = json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _covered(asset: str, candidates: tuple[str, ...]) -> bool:
    """Conservative, literal hostname or same-family network coverage only."""
    kind, target = _asset(asset)
    for candidate in candidates:
        source_kind, source = _asset(candidate)
        if kind == source_kind == "host" and target == source:
            return True
        if kind == source_kind == "network" and (
            target.version == source.version and target.subnet_of(source)
        ):
            return True
    return False


def prepare_rejected_revision(
    original: AssessmentRequestRecord,
    *,
    assets: list[str] | None,
    risk: int | None,
    notes: str | None,
) -> dict:
    """Prepare a fresh request and show effective scope change, no database writes."""
    if (original.status is not RequestStatus.REJECTED
            or original.requested_mode is not AssessmentMode.AUTHORIZED_ASSESSMENT):
        raise ClientRequestError(
            "only an independently REJECTED authorized-assessment request can be resubmitted"
        )
    old_assets = canonical_assets(list(original.requested_assets))
    old_risk = int(original.requested_risk)
    if not 1 <= old_risk <= 4:
        raise ClientRequestError("prior request risk level is not a supported client risk")
    if (assets is None and risk is None and notes is None):
        raise ClientRequestError("provide at least one explicit revision")
    new_assets = canonical_assets(assets) if assets is not None else old_assets
    new_risk = risk if risk is not None else old_risk
    new_notes = notes if notes is not None else original.notes
    if (new_assets == old_assets and new_risk == old_risk
            and new_notes.strip() == original.notes.strip()):
        raise ClientRequestError("new request would be identical to the rejected one")
    introduced = [item for item in new_assets if not _covered(item, old_assets)]
    removed = [item for item in old_assets if not _covered(item, new_assets)]
    wider_risk = type(new_risk) is int and new_risk > old_risk
    expansion = bool(introduced or wider_risk)
    version = original_revision_sha256(original)
    explanation = (
        new_notes.strip() + "\n"
        + "CLIENT REVISION REQUEST (not operator approval, not consent).\n"
        + "Earlier rejected request: " + original.request_id + "\n"
        + "Original review-snapshot SHA-256 (unsigned): " + version
    ).strip()
    payload = prepare_request(list(new_assets), new_risk, explanation)
    payload.update({
        "previous_request_id": original.request_id,
        "previous_status": "rejected",
        "previous_risk": old_risk,
        "previous_assets": list(old_assets),
        "previous_record_sha256": version,
        "newly_introduced_assets": introduced,
        "removed_or_narrowed_assets": removed,
        "risk_increased": bool(wider_risk),
        "scope_expansion_requires_confirmation": expansion,
        "updates_previous_request": False,
        "operator_decision_inherited": False,
        "grant_issued": False,
        "authorized": False,
        "consent_verified": False,
        "scan_allowed": False,
        "dispatch_allowed": False,
    })
    # Bind the complete proposed revision, not merely the rejected original.
    # A changed asset/risk/notes value after preview must require a new review.
    revision_identity = {
        "format": "LIGHTUP_CLIENT_REJECTED_REVISION_V1",
        "original_id": original.request_id,
        "original_record_sha256": version,
        "proposed_assets": payload["requested_assets"],
        "proposed_risk": payload["requested_risk"],
        "proposed_notes": payload["notes"],
        "newly_introduced_assets": introduced,
        "removed_or_narrowed_assets": removed,
        "risk_increased": bool(wider_risk),
        "needs_scope_expansion_confirmation": expansion,
    }
    revision_bytes = json.dumps(
        revision_identity, ensure_ascii=True, sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    payload["revision_sha256"] = hashlib.sha256(revision_bytes).hexdigest()
    payload["revision_authenticated"] = False
    payload["revision_authorized"] = False
    return payload
