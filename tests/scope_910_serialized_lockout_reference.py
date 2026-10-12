"""TEST-ONLY SQLite reference for independent login failure race acceptance #910.

Not imported by LightUp production, not an installed authentication boundary.
The intentionally conservative BEGIN IMMEDIATE critical section shows that the
lost-update regression can be made GREEN, while revealing the global-writer
contention and slow password-verification tradeoff. Source owner owns any fix.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from lightup.domain import AccountLockedError, DomainStore, utcnow


class SerializedLoginReference:
    """Synthetic reference, NOT a production-safe authentication adapter."""

    def __init__(self, store: DomainStore):
        if type(store) is not DomainStore:
            raise TypeError("reference requires exact DomainStore")
        self._store = store

    def authenticate(self, email: str, password: str) -> Any:
        if type(email) is not str or type(password) is not str:
            raise TypeError("reference login fields require built-in strings")
        canonical = email.strip().lower()
        if not canonical:
            raise ValueError("reference email is empty")

        # SQLite BEGIN IMMEDIATE locks writers across the entire DB, not
        # merely this account. This is deliberate only for a tiny offline
        # fixture and MUST NOT be installed as the production implementation.
        with self._store._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                now = utcnow()
                row = con.execute(
                    "SELECT failures,locked_until FROM login_failures WHERE email=?",
                    (canonical,),
                ).fetchone()
                if row is not None and row["locked_until"]:
                    if datetime.fromisoformat(row["locked_until"]) > now:
                        raise AccountLockedError("too many failed sign-ins; try again later")

                # In the reference the verifier is a test stub; real password
                # hashing here would hold a database-wide writer lock.
                user = self._store.verify_password(canonical, password)
                if user is not None:
                    con.execute("DELETE FROM login_failures WHERE email=?", (canonical,))
                else:
                    failures = (row["failures"] if row is not None else 0) + 1
                    locked_until = None
                    if failures >= self._store.LOGIN_MAX_FAILURES:
                        locked_until = (
                            now + timedelta(seconds=self._store.LOGIN_LOCKOUT_SECONDS)
                        ).isoformat()
                        failures = 0
                    con.execute(
                        "INSERT INTO login_failures(email,failures,locked_until) "
                        "VALUES(?,?,?) ON CONFLICT(email) DO UPDATE SET "
                        "failures=excluded.failures, locked_until=excluded.locked_until",
                        (canonical, failures, locked_until),
                    )
                con.commit()
                return user
            except BaseException:
                con.rollback()
                raise
