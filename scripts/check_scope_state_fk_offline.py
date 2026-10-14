"""Synthetic-only foreign-key/run-provenance review. No target/production DB IO."""
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
    "valid_run_evidence_stored",
    "no_orphan_rows_persisted",
)


def probe(factory: Callable[[str], object]) -> dict[str, object]:
    checks = dict.fromkeys(CHECK_NAMES, False)
    try:
        with tempfile.TemporaryDirectory(prefix="lightup-fk-review-") as directory:
            store = factory(str(Path(directory) / "synthetic.db"))
            with store.connect() as connection:
                row = connection.execute("PRAGMA foreign_keys").fetchone()
                checks["new_connection_fk_enabled"] = bool(row and row[0] == 1)

            missing = "00000000-0000-4000-8000-000000000170"
            try:
                store.add_evidence(missing, "fixture", "review", "offline", b"synthetic", {})
            except sqlite3.IntegrityError:
                checks["orphan_evidence_denied"] = True
            try:
                store.acquire_lease(missing, "fixture", "offline-worker", ttl_seconds=60)
            except sqlite3.IntegrityError:
                checks["orphan_lease_denied"] = True

            existing = store.create_run("127.0.0.1", activation_mode="plan_only")
            evidence = store.add_evidence(existing, "fixture", "review", "offline", b"control", {})
            checks["valid_run_evidence_stored"] = store.get_evidence(evidence).run_id == existing
            with store.connect() as connection:
                orphan_evidence = connection.execute(
                    "SELECT COUNT(*) FROM evidence WHERE run_id=?", (missing,)
                ).fetchone()[0]
                orphan_lease = connection.execute(
                    "SELECT COUNT(*) FROM capability_leases WHERE run_id=?", (missing,)
                ).fetchone()[0]
                checks["no_orphan_rows_persisted"] = not (orphan_evidence or orphan_lease)
    except Exception:
        # Do not disclose paths, data or exception details in machine-readable receipts.
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
