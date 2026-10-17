"""Non-authorizing, offline grant/engagement tenant-lineage snapshot inspection.

Issue #1561. Unwired and intentionally independent from DomainStore, active
authorization, scanners, handlers and release decisions. Reads ONLY a
caller-designated, quiescent SQLite snapshot via immutable+query_only.
No grant IDs, tenant IDs, scopes or paths appear in receipts.

REVIEW_ONLY is informational (exit 3), never execution permission. Any
ambiguity is HOLD (exit 2). Exit 0 is intentionally impossible.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import sys
from pathlib import Path
from urllib.parse import quote

MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_GRANTS = 10_000
MAX_ENGAGEMENTS = 10_000
_ALLOWED_REASON = frozenset({
    "coherent_offline_snapshot", "tenant_lineage_mismatch",
    "orphaned_engagement", "invalid_input", "unsafe_snapshot",
    "invalid_schema", "invalid_record", "too_many_grants",
    "snapshot_changed", "orphaned_client", "too_many_engagements",
})
_REQUIRED = {
    "clients": ("client_id",),
    "engagements": ("engagement_id", "client_id"),
    "authorization_grants": ("grant_id", "engagement_id", "client_id"),
}
_FLAGS = {
    "authorized": False,
    "consent_verified": False,
    "grants_allowed": False,
    "scans_allowed": False,
    "dispatch_allowed": False,
    "merge_allowed": False,
    "deploy_allowed": False,
    "release_allowed": False,
}


class _HOLD(Exception):
    def __init__(self, reason: str):
        assert reason in _ALLOWED_REASON
        self.reason = reason


def _receipt(reason: str, coherent: int = 0, mismatch: int = 0,
             orphan: int = 0, missing_client: int = 0,
             unbound_engagements: int = 0, engagements_checked: int = 0) -> dict:
    assert reason in _ALLOWED_REASON
    return {
        # Explicit schema epoch prevents old consumers silently mistaking the
        # expanded three-table receipt for the previous two-table contract.
        "receipt_version": 2,
        "status": "REVIEW_ONLY" if reason == "coherent_offline_snapshot" else "HOLD",
        "reason": reason,
        "coherent": coherent,
        "mismatch": mismatch,
        "orphan": orphan,
        "missing_client": missing_client,
        "unbound_engagements": unbound_engagements,
        "engagements_checked": engagements_checked,
        "total": coherent + mismatch + orphan + missing_client,
        **_FLAGS,
    }


def _path_snapshot(path: Path):
    # No path strings are ever emitted, including during failures.
    try:
        cursor = path
        while True:
            node = cursor.lstat()
            if stat.S_ISLNK(node.st_mode):
                raise _HOLD("unsafe_snapshot")
            if cursor == cursor.parent:
                break
            cursor = cursor.parent
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise _HOLD("unsafe_snapshot")
        if not 0 < info.st_size <= MAX_SNAPSHOT_BYTES:
            raise _HOLD("unsafe_snapshot")
        for suffix in ("-wal", "-shm", "-journal"):
            if os.path.lexists(str(path) + suffix):
                raise _HOLD("unsafe_snapshot")
        return (
            info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns,
        )
    except _HOLD:
        raise
    except (OSError, ValueError, UnicodeError):
        raise _HOLD("unsafe_snapshot") from None


def _snapshot_sha256(path: Path, expected_metadata: tuple) -> bytes:
    """Read only the exact checked inode; hash a bounded offline snapshot.

    Opening via O_NOFOLLOW closes the last-component symlink race. If the
    platform lacks that flag, reject rather than quietly degrade security.
    """
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise _HOLD("unsafe_snapshot")
    fd = -1
    try:
        fd = os.open(str(path), os.O_RDONLY | nofollow |
                     getattr(os, "O_CLOEXEC", 0))
        info = os.fstat(fd)
        got = (info.st_dev, info.st_ino, info.st_size,
               info.st_mtime_ns, info.st_ctime_ns)
        if got != expected_metadata or not stat.S_ISREG(info.st_mode):
            raise _HOLD("snapshot_changed")
        digest = hashlib.sha256()
        count = 0
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            count += len(block)
            if count > MAX_SNAPSHOT_BYTES:
                raise _HOLD("snapshot_changed")
            digest.update(block)
        if count != info.st_size:
            raise _HOLD("snapshot_changed")
        return digest.digest()
    except _HOLD:
        raise
    except (OSError, OverflowError, MemoryError):
        raise _HOLD("unsafe_snapshot") from None
    finally:
        if fd >= 0:
            os.close(fd)


def _offline_sql_authorizer(
    action: int, name: str | None, argument: str | None,
    database: str | None, origin: str | None,
) -> int:
    """Allow only the static SQL reads and two inspection PRAGMA operations.

    Additional defense beyond immutable SQLite + query_only; this callback
    cannot by itself authenticate the database or guarantee atomicity.
    """
    if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ,
                  sqlite3.SQLITE_FUNCTION):
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA and type(name) is str:
        if name.lower() in ("quick_check", "table_info"):
            return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _guard_schema(con: sqlite3.Connection) -> None:
    # Reject views, missing tables and schema variants without attempting
    # any repair. With PKs, a join cannot multiply rows ambiguously.
    table_rows = con.execute(
        "SELECT name,type FROM sqlite_schema "
        "WHERE name IN ('clients','engagements','authorization_grants')"
    ).fetchall()
    if len(table_rows) != 3 or any(kind != "table" for _, kind in table_rows):
        raise _HOLD("invalid_schema")
    for table, columns in _REQUIRED.items():
        details = con.execute(f"PRAGMA table_info({table})").fetchall()
        names = [row[1] for row in details]
        if not details or len(names) != len(set(names)):
            raise _HOLD("invalid_schema")
        if any(column not in names for column in columns):
            raise _HOLD("invalid_schema")
        pk = [row[1] for row in details if row[5] != 0]
        if pk != [columns[0]]:
            raise _HOLD("invalid_schema")


def inspect_offline_grant_tenants(snapshot_path: str) -> dict:
    """Summarize only counts from a quiescent, offline synthetic DB copy.

    Never use this result as a source of authorization or production approval.
    """
    try:
        if type(snapshot_path) is not str or not snapshot_path:
            raise _HOLD("invalid_input")
        if "\x00" in snapshot_path or len(snapshot_path.encode("utf-8")) > 4096:
            raise _HOLD("invalid_input")
        path = Path(snapshot_path).absolute()
        before = _path_snapshot(path)
        original_hash = _snapshot_sha256(path, before)
        uri = "file:" + quote(str(path), safe="/") + "?mode=ro&immutable=1"
        con = sqlite3.connect(uri, uri=True, timeout=0)
        try:
            # Configure safety settings BEFORE the restrictive authorizer.
            # Fail closed if this SQLite build does not support the expected
            # defensive settings. Neither statement writes to the snapshot.
            con.execute("PRAGMA trusted_schema=OFF")
            con.execute("PRAGMA query_only=ON")
            if (con.execute("PRAGMA trusted_schema").fetchone() != (0,)
                    or con.execute("PRAGMA query_only").fetchone() != (1,)):
                raise _HOLD("unsafe_snapshot")
            con.set_authorizer(_offline_sql_authorizer)
            ticks = [0]

            def bounded_sql():
                ticks[0] += 1
                return 1 if ticks[0] > 4_000 else 0

            con.set_progress_handler(bounded_sql, 250)
            check = con.execute("PRAGMA quick_check(1)").fetchall()
            if check != [("ok",)]:
                raise _HOLD("invalid_schema")
            _guard_schema(con)
            rows = con.execute(
                "SELECT g.grant_id,g.engagement_id,g.client_id,"
                "e.engagement_id,e.client_id,c.client_id "
                "FROM authorization_grants AS g "
                "LEFT JOIN engagements AS e ON "
                "e.engagement_id COLLATE BINARY = g.engagement_id COLLATE BINARY "
                "LEFT JOIN clients AS c ON "
                "c.client_id COLLATE BINARY = e.client_id COLLATE BINARY "
                "LIMIT ?",
                (MAX_GRANTS + 1,),
            ).fetchall()
            if len(rows) > MAX_GRANTS:
                raise _HOLD("too_many_grants")
            coherent = mismatch = orphan = missing_client = 0
            for (grant, engagement, client, owner_engagement, owner_client,
                 actual_client) in rows:
                if not all(type(v) is str and 0 < len(v) <= 1024
                           for v in (grant, engagement, client)):
                    raise _HOLD("invalid_record")
                if owner_engagement is None:
                    orphan += 1
                elif (
                    type(owner_engagement) is not str
                    or owner_engagement != engagement
                    or type(owner_client) is not str
                    or not owner_client or len(owner_client) > 1024
                ):
                    raise _HOLD("invalid_record")
                elif actual_client is None:
                    # A grant and engagement agreeing on an imaginary tenant
                    # must never produce a false REVIEW_ONLY receipt.
                    missing_client += 1
                elif type(actual_client) is not str or actual_client != owner_client:
                    raise _HOLD("invalid_record")
                elif client != owner_client:
                    mismatch += 1
                else:
                    coherent += 1

            # Engagements without any grants still need a real client owner.
            # An empty grant table must not disguise a broken engagement.
            engagement_rows = con.execute(
                "SELECT e.engagement_id,e.client_id,c.client_id "
                "FROM engagements AS e "
                "LEFT JOIN clients AS c ON "
                "c.client_id COLLATE BINARY = e.client_id COLLATE BINARY "
                "LIMIT ?",
                (MAX_ENGAGEMENTS + 1,),
            ).fetchall()
            if len(engagement_rows) > MAX_ENGAGEMENTS:
                raise _HOLD("too_many_engagements")
            engagements_checked = len(engagement_rows)
            unbound_engagements = 0
            for engagement_id, owner_client, actual_client in engagement_rows:
                if not all(
                    type(v) is str and 0 < len(v) <= 1024
                    for v in (engagement_id, owner_client)
                ):
                    raise _HOLD("invalid_record")
                if actual_client is None:
                    unbound_engagements += 1
                elif type(actual_client) is not str or actual_client != owner_client:
                    raise _HOLD("invalid_record")
        finally:
            con.close()
        if _path_snapshot(path) != before:
            raise _HOLD("snapshot_changed")
        if _snapshot_sha256(path, before) != original_hash:
            raise _HOLD("snapshot_changed")
        counts = (coherent, mismatch, orphan, missing_client,
                  unbound_engagements, engagements_checked)
        if orphan:
            return _receipt("orphaned_engagement", *counts)
        if missing_client or unbound_engagements:
            return _receipt("orphaned_client", *counts)
        if mismatch:
            return _receipt("tenant_lineage_mismatch", *counts)
        return _receipt("coherent_offline_snapshot", *counts)
    except _HOLD as error:
        return _receipt(error.reason)
    except (OSError, sqlite3.Error, ValueError, OverflowError,
            UnicodeError, MemoryError):
        return _receipt("unsafe_snapshot")


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2 or arguments[0] != "--offline-copy":
        result = _receipt("invalid_input")
    else:
        result = inspect_offline_grant_tenants(arguments[1])
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 3 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
