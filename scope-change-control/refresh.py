"""Original-domain Casebook: authenticated current vs private historical change handoff.

Standalone additive operator utility. No grant, STOP, consent, scan or target mutation.
Run with PYTHONPATH=src python3 scope-change-control/refresh.py --help.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime
from getpass import getpass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys

from lightup.auth_casebook import (
    AUTHORITY, CasebookHold, _write_private_json, authenticated_casebook,
)

MAX_SOURCE = 512 * 1024
FAMILIES = {
    "requests": "request_id",
    "engagements": "engagement_id",
    "grants": "grant_id",
    "risk_approvals": "approval_id",
    "case_overview": "engagement_id",
}
SCHEMA = "lightup.auth_casebook.v1"


class ReviewHold(ValueError):
    """No positive execution inference may be derived from this report."""


def _duplicate_pairs(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ReviewHold("duplicate JSON source key")
        result[key] = value
    return result


def _private_read(path: str) -> tuple[dict, str]:
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_size < 2
                or info.st_size > MAX_SOURCE or info.st_uid != os.geteuid()
                or info.st_mode & 0o077):
            raise ReviewHold("previous original private source file not admitted")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw = stream.read(MAX_SOURCE + 1)
        if len(raw) > MAX_SOURCE:
            raise ReviewHold("previous source exceeds size bound")
        text = raw.decode("utf-8", errors="strict")
        doc = json.loads(text, object_pairs_hook=_duplicate_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(ReviewHold("invalid numeric constant")))
        if type(doc) is not dict:
            raise ReviewHold("invalid original source shape")
        return doc, sha256(raw).hexdigest()
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReviewHold("previous private source is unavailable or malformed") from None
    finally:
        if fd is not None:
            os.close(fd)


def _identity(value: object) -> bool:
    return (type(value) is str and 1 <= len(value) <= 180
            and value == value.strip()
            and all(32 < ord(c) != 127 for c in value))


def _timestamp(value: object) -> datetime:
    if (type(value) is not str or len(value) > 80
            or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)", value)):
        raise ReviewHold("timestamp must be explicit timezone-aware ISO")
    try:
        instant = datetime.fromisoformat(value)
        if instant.utcoffset() is None:
            raise ValueError("naive")
        return instant
    except (ValueError, OverflowError):
        raise ReviewHold("noncanonical original snapshot time") from None


def _admit(doc: dict) -> dict[str, dict[str, dict]]:
    if (type(doc) is not dict or doc.get("schema") != SCHEMA
            or doc.get("status") != "REVIEW_ONLY"
            or doc.get("source") != "original_persisted_domain_unverified"
            or not _identity(doc.get("client_id"))):
        raise ReviewHold("not original source snapshot")
    for field in AUTHORITY:
        if doc.get(field) is not False:
            raise ReviewHold("source falsely asserts authority")
    _timestamp(doc.get("as_of"))
    declared = doc.get("declared_counts")
    if type(declared) is not dict:
        raise ReviewHold("original declared counts absent")
    indexed: dict[str, dict[str, dict]] = {}
    for family, identity in FAMILIES.items():
        records = doc.get(family)
        if type(records) is not list or len(records) > 200:
            raise ReviewHold("invalid original source family")
        index: dict[str, dict] = {}
        for row in records:
            if type(row) is not dict or not _identity(row.get(identity)) or row[identity] in index:
                raise ReviewHold("duplicate or corrupted original source identity")
            index[row[identity]] = row
        indexed[family] = index
        if family != "case_overview" and (
                type(declared.get(family)) is not int or declared[family] != len(records)):
            raise ReviewHold("original family count does not reconcile")
    if set(indexed["case_overview"]) != set(indexed["engagements"]):
        raise ReviewHold("missing original case membership")
    for eid, case in indexed["case_overview"].items():
        if (case.get("status") != indexed["engagements"][eid].get("status")
                or not _identity(case.get("attention"))
                or not _identity(case.get("next_review_action"))
                or type(case.get("grant_count")) is not int
                or type(case.get("risk_record_count")) is not int
                or not 0 <= case["grant_count"] <= 200
                or not 0 <= case["risk_record_count"] <= 200):
            raise ReviewHold("original case cross-source fields inconsistent")
        if case["grant_count"] != sum(
                row.get("engagement_id") == eid for row in indexed["grants"].values()):
            raise ReviewHold("original case/grant count drift")
        if case["risk_record_count"] != sum(
                row.get("engagement_id") == eid for row in indexed["risk_approvals"].values()):
            raise ReviewHold("original case/risk count drift")
    for grant in indexed["grants"].values():
        engagement = grant.get("engagement_id")
        if (engagement is not None and engagement not in indexed["engagements"]):
            raise ReviewHold("unknown original grant engagement")
        if (not _identity(grant.get("request_link_observation"))
                or not _identity(grant.get("validity_observation"))
                or type(grant.get("max_risk")) is not int
                or not 0 <= grant["max_risk"] <= 5):
            raise ReviewHold("malformed original grant observation")
    for risk in indexed["risk_approvals"].values():
        engagement = risk.get("engagement_id")
        if (engagement is not None and engagement not in indexed["engagements"]
                or type(risk.get("source_tenant_matches")) is not bool
                or not _identity(risk.get("decision_provenance_observation"))):
            raise ReviewHold("malformed original risk observation")
    for request in indexed["requests"].values():
        if (request.get("status") not in
                ("submitted", "under_review", "approved", "rejected")
                or type(request.get("requested_risk")) is not int
                or not 0 <= request["requested_risk"] <= 5
                or type(request.get("decision_recorded")) is not bool):
            raise ReviewHold("malformed original request observation")
    if (type(declared.get("case_attention_hold")) is not int
            or declared["case_attention_hold"] != sum(
                x["attention"].startswith("HOLD_") for x in indexed["case_overview"].values())):
        raise ReviewHold("case HOLD total contradicts original rows")
    return indexed


def _priority(family: str, kind: str, old: dict | None, record: dict | None) -> str:
    if kind == "MISSING_FROM_NEW_SOURCE" or family in ("grants", "case_overview"):
        return "URGENT_HUMAN_REVIEW"
    if any(candidate is not None and (
            candidate.get("status") == "approved"
            or any(type(v) is str and v.startswith("HOLD_") for v in candidate.values()))
           for candidate in (old, record)):
        return "URGENT_HUMAN_REVIEW"
    return "REVIEW_ONLY"


def _diff(before: dict, now: dict, old_sha: str) -> dict:
    old = _admit(before)
    new = _admit(now)
    if before["client_id"] != now["client_id"]:
        raise ReviewHold("historical/current original tenant mismatch")
    if not _timestamp(before["as_of"]) < _timestamp(now["as_of"]):
        raise ReviewHold("original timestamps not strictly increasing")
    result = []
    for family in FAMILIES:
        for identity in sorted(set(old[family]) | set(new[family])):
            a, b = old[family].get(identity), new[family].get(identity)
            if a == b:
                continue
            kind = ("NEW_SOURCE_ROW" if a is None else
                    "MISSING_FROM_NEW_SOURCE" if b is None else "SOURCE_FIELDS_CHANGED")
            fields = (sorted(
                key for key in set(a) | set(b) if a.get(key) != b.get(key)
            ) if a is not None and b is not None else [])
            result.append({
                "family": family, "original_id": identity, "change": kind,
                "priority": _priority(family, kind, a, b),
                "changed_fields_only": fields,
                "human_follow_up": "UNREVIEWED",
            })
    # A changed ORIGINAL approved-request record can affect an unchanged grant
    # that references it. Existing source-grant bytes are not permission proof.
    changed_requests = {
        rid for rid in set(old["requests"]) | set(new["requests"])
        if old["requests"].get(rid) != new["requests"].get(rid)
    }
    unchanged_linked = []
    for gid in sorted(set(old["grants"]) & set(new["grants"])):
        grant = new["grants"][gid]
        if grant != old["grants"][gid]:
            continue  # This grant is already a normal source-change row.
        request_id = grant.get("approved_request_id")
        if type(request_id) is not str or request_id not in changed_requests:
            continue
        prior_req = old["requests"].get(request_id)
        current_req = new["requests"].get(request_id)
        unchanged_linked.append({
            "original_grant_id": gid,
            "recorded_request_id": request_id,
            "original_engagement_id": grant.get("engagement_id"),
            "recorded_request_status_before": (
                prior_req.get("status") if prior_req is not None else "not recorded"),
            "recorded_request_status_after": (
                current_req.get("status") if current_req is not None else "not recorded"),
            "human_follow_up": "UNREVIEWED",
            "authority_claim": False,
        })
    counts = Counter(f"{r['family']}/{r['change']}/{r['priority']}" for r in result)
    return {
        "schema": "lightup.casebook_change_private_review.v1",
        "disposition": "HOLD_HUMAN_REVIEW",
        "original_source_verified": False,
        "action_time_revocation_verified": False,
        **AUTHORITY,
        "tenant_original_id": now["client_id"],
        "source_sha256_unsigned": [
            old_sha,
            None,
        ],
        "source_times": [before["as_of"], now["as_of"]],
        "changes": result,
        "unchanged_grant_request_dependencies": unchanged_linked,
        "aggregate_without_original_ids": {
            "snapshot_count": 2, "changed_record_count": len(result),
            "linked_unchanged_grant_attention_count": len(unchanged_linked),
            "urgent_review_count": sum(r["priority"] == "URGENT_HUMAN_REVIEW" for r in result),
            "source_delta_counts": dict(sorted(counts.items())),
        },
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="LightUp private original Casebook history → current source change, review only.")
    p.add_argument("--database", required=True, help="original local DomainStore SQLite file")
    p.add_argument("--email", required=True, help="original operator/client account")
    p.add_argument("--client", help="operator's exact selected tenant; client must match own")
    p.add_argument("--previous", required=True, help="older original 0600 Casebook JSON")
    p.add_argument("--output-private", required=True, help="new exclusive 0600 human review file")
    args = p.parse_args(argv)
    try:
        previous, digest = _private_read(args.previous)
        # All actual role, tenant, lockout and persisted-source rules are delegated
        # to the original owner-maintained DomainStore and Casebook.
        now = authenticated_casebook(
            args.database, email=args.email, password=getpass("Existing account password: "),
            client_id=args.client,
        )
        document = _diff(previous, now, digest)
        document["source_sha256_unsigned"][1] = sha256(
            (json.dumps(now, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
        ).hexdigest()
        _write_private_json(args.output_private, document)
        print(json.dumps({
            "disposition": "HOLD_HUMAN_REVIEW",
            "private_file_written": True,
            "aggregate": document["aggregate_without_original_ids"],
            "all_authority_claims": False,
        }, sort_keys=True))
        return 2
    except (ReviewHold, CasebookHold, PermissionError, ValueError, OSError) as exc:
        print("HOLD: original source/authentication/private output not admitted", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
