"""Disposable SQLite foreign-key and run-provenance reviewer; never authorizes work."""
from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

AUTHORITY = {
    "authorization_verified": False,
    "permit_issued": False,
    "execution_enabled": False,
    "merge_approved": False,
    "release_approved": False,
}
CHECK_NAMES = (
    "new_connection_fk_enabled",
    "orphan_evidence_denied",
    "orphan_lease_denied",
    "raw_orphan_evidence_denied",
    "valid_run_evidence_stored",
    "registered_run_provenance_exact",
    "connection_fk_consistent",
    "delete_cascades_evidence",
    "delete_cascades_lease",
    "sqlite_foreign_key_check_clean",
    "no_orphan_rows_persisted",
)

# No user-input database paths or live target identities are accepted.
MISSING_RUN = "00000000-0000-4000-8000-000000000170"


def probe(factory: Callable[[str], object]) -> dict[str, object]:
    checks = dict.fromkeys(CHECK_NAMES, False)
    try:
        with tempfile.TemporaryDirectory(prefix="lightup-fk-review-") as directory:
            store = factory(str(Path(directory) / "synthetic.db"))
            with store.connect() as connection:
                flag = connection.execute("PRAGMA foreign_keys").fetchone()
                checks["new_connection_fk_enabled"] = bool(flag and flag[0] == 1)

            try:
                store.add_evidence(MISSING_RUN, "fixture", "review", "offline", b"synthetic", {})
            except sqlite3.IntegrityError:
                checks["orphan_evidence_denied"] = True

            try:
                store.acquire_lease(MISSING_RUN, "fixture", "offline-worker", ttl_seconds=60)
            except sqlite3.IntegrityError:
                checks["orphan_lease_denied"] = True

            # High-level validation alone must not mask a broken connection-level FK.
            with store.connect() as connection:
                flag = connection.execute("PRAGMA foreign_keys").fetchone()
                checks["connection_fk_consistent"] = bool(flag and flag[0] == 1)
                try:
                    connection.execute(
                        "INSERT INTO evidence("
                        "evidence_id,run_id,capability_id,kind,source,sha256,"
                        "metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
                        ("00000000-0000-4000-8000-000000000171", MISSING_RUN,
                         "fixture", "review", "offline", "0" * 64, "{}", "2026-10-14T00:00:00Z"),
                    )
                except sqlite3.IntegrityError:
                    checks["raw_orphan_evidence_denied"] = True

            run_id = store.create_run("127.0.0.1", activation_mode="plan_only")
            evidence_id = store.add_evidence(run_id, "fixture", "review", "offline", b"control", {})
            checks["valid_run_evidence_stored"] = store.get_evidence(evidence_id).run_id == run_id
            store.acquire_lease(run_id, "fixture", "offline-worker", ttl_seconds=60)

            # Persisted authority has to be exactly the synthetic plan-only run.
            with store.connect() as connection:
                rows = connection.execute(
                    "SELECT run_id,target,activation_mode,authorization_ref,status "
                    "FROM runs WHERE run_id=?", (run_id,)
                ).fetchall()
                checks["registered_run_provenance_exact"] = len(rows) == 1 and (
                    rows[0]["run_id"] == run_id
                    and rows[0]["target"] == "127.0.0.1"
                    and rows[0]["activation_mode"] == "plan_only"
                    and rows[0]["authorization_ref"] is None
                    and rows[0]["status"] == "planned"
                )
                orphan_evidence = connection.execute(
                    "SELECT COUNT(*) FROM evidence WHERE run_id=?", (MISSING_RUN,)
                ).fetchone()[0]
                orphan_lease = connection.execute(
                    "SELECT COUNT(*) FROM capability_leases WHERE run_id=?", (MISSING_RUN,)
                ).fetchone()[0]
                checks["no_orphan_rows_persisted"] = not (orphan_evidence or orphan_lease)
                checks["sqlite_foreign_key_check_clean"] = not connection.execute(
                    "PRAGMA foreign_key_check"
                ).fetchone()

            # CASCADE integrity must also hold on a *subsequent* connection.
            with store.connect() as connection:
                connection.execute("DELETE FROM runs WHERE run_id=?", (run_id,))
            with store.connect() as connection:
                checks["delete_cascades_evidence"] = connection.execute(
                    "SELECT COUNT(*) FROM evidence WHERE evidence_id=?", (evidence_id,)
                ).fetchone()[0] == 0
                checks["delete_cascades_lease"] = connection.execute(
                    "SELECT COUNT(*) FROM capability_leases WHERE run_id=?", (run_id,)
                ).fetchone()[0] == 0
                checks["sqlite_foreign_key_check_clean"] &= not connection.execute(
                    "PRAGMA foreign_key_check"
                ).fetchone()
    except Exception:
        # Explicitly avoid leaking local paths, query contents, or exception messages.
        return {"status": "HOLD", "reason": "PROBE_UNAVAILABLE", "checks": checks, **AUTHORITY}

    good = all(checks.values())
    return {
        "status": "REVIEW_ONLY" if good else "HOLD",
        "reason": "SYNTHETIC_BOUNDARY_VALID" if good else "RUN_PROVENANCE_BOUNDARY_UNSATISFIED",
        "checks": checks,
        **AUTHORITY,
    }


def main() -> int:
    try:
        from lightup.state import StateStore
        result = probe(StateStore)
    except Exception:
        result = {
            "status": "HOLD",
            "reason": "PROBE_UNAVAILABLE",
            "checks": dict.fromkeys(CHECK_NAMES, False),
            **AUTHORITY,
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
