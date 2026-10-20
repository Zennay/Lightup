"""Opt-in carryover of PRIVATE human coordination across original source revisions.

This never migrates changed finding source content or claims real source identity.
Only a separately confirmed human can use this helper to prepare a new local
workdesk; it does not mutate the original archive or plan.
"""
from __future__ import annotations

from .private_export_handoff import _read_archive
from .private_export_workdesk import _load_resume


def migrate_exact_unchanged(
    earlier_zip: str,
    earlier_workplan: str,
    new_manifest: dict,
    new_rows: list[dict[str, str]],
) -> tuple[dict[str, dict], dict[str, int]]:
    old_manifest, old_rows = _read_archive(earlier_zip)
    old_workplan = _load_resume(earlier_workplan, old_manifest, old_rows)
    if any(old_manifest[field] != new_manifest[field] for field in (
        "declared_client_id", "declared_engagement_id"
    )):
        raise ValueError("HUMAN source context declarations differ")
    old = {row["finding_id"]: row for row in old_rows}
    migrated: dict[str, dict] = {}
    counts = {"carried": 0, "new": 0, "changed": 0, "absent": 0}
    for row in new_rows:
        identity = row["finding_id"]
        if identity in old and row == old[identity]:
            migrated[identity] = dict(old_workplan[identity])
            counts["carried"] += 1
        else:
            migrated[identity] = {
                "finding_id": identity, "stage": "unassigned", "owner_alias": "",
                "due_date": "", "human_note": "",
            }
            counts["changed" if identity in old else "new"] += 1
    counts["absent"] = len(set(old) - set(migrated))
    return migrated, counts
