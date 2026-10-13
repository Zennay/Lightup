"""Optional read-only, privacy-minimized evidence identifier shape inventory.

This is a *diagnostic*, not installed in StateStore or an authorization gate.
Only aggregate counts leave this module; row IDs never enter logs or results.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .evidence_id_admission import canonical_evidence_id

_DEFAULT_ROW_BUDGET = 100_000
_FETCH_BATCH = 128


@dataclass(frozen=True, slots=True)
class EvidenceIdInventory:
    total: int
    canonical_uuid4: int
    noncanonical_text: int
    nontext_or_null: int


def inspect_evidence_id_shapes(
    database_path: str | Path, *, max_rows: int = _DEFAULT_ROW_BUDGET
) -> EvidenceIdInventory:
    """Count stored evidence-ID shapes without writing or disclosing any ID.

    Opens an existing SQLite database in read-only mode, selects only the
    identifier's SQLite storage class and *at most 36 text characters* for
    exact-length candidates, and fetches at most 128 rows at once. This is
    bounded Python-facing row materialization, NOT a process RSS/CPU bound.
    No migration, coercion, repairs, tenant checks, or grants are performed.
    """
    if not isinstance(database_path, (str, Path)):
        raise ValueError("evidence inventory requires a filesystem path")
    if type(max_rows) is not int or not 1 <= max_rows <= _DEFAULT_ROW_BUDGET:
        raise ValueError("evidence inventory row budget must be 1..100000")
    try:
        resolved = Path(database_path).resolve(strict=True)
        if not resolved.is_file():
            raise ValueError("evidence inventory requires an existing SQLite file")
    except (OSError, RuntimeError, UnicodeError):
        raise ValueError("evidence inventory requires an existing SQLite file") from None

    connection = None
    try:
        # The SQLite URI is formed from a normalized file path, never from
        # caller-supplied SQL. mode=ro forbids updates, schema edits and creation.
        connection = sqlite3.connect(resolved.as_uri() + "?mode=ro", uri=True)
        connection.execute("PRAGMA query_only=ON")
        # This diagnostic only understands the real StateStore evidence table.
        # A foreign database/view with an "evidence_id" column must not produce
        # plausible-looking migration/compatibility counts.
        schema_rows = connection.execute(
            "SELECT type, sql FROM sqlite_schema WHERE name='evidence'"
        ).fetchall()
        if (
            len(schema_rows) != 1
            or schema_rows[0][0] != "table"
            or not isinstance(schema_rows[0][1], str)
            or schema_rows[0][1].lstrip().lower().startswith(
                "create virtual table"
            )
        ):
            raise ValueError("evidence inventory unavailable or invalid SQLite schema")
        columns = {
            row[1]: (row[2].upper(), row[5])
            for row in connection.execute('PRAGMA table_info("evidence")')
        }
        mandatory = (
            "evidence_id", "run_id", "capability_id", "kind",
            "source", "sha256", "metadata_json", "created_at",
        )
        if (
            any(name not in columns for name in mandatory)
            or columns["evidence_id"] != ("TEXT", 1)
        ):
            raise ValueError("evidence inventory unavailable or invalid SQLite schema")
        cursor = connection.execute(
            "SELECT typeof(evidence_id), "
            "CASE WHEN typeof(evidence_id)='text' "
            "AND length(evidence_id)=36 THEN evidence_id ELSE NULL END "
            "FROM evidence"
        )
        total = canonical = other_text = nontext = 0
        while True:
            batch = cursor.fetchmany(_FETCH_BATCH)
            if not batch:
                break
            if total + len(batch) > max_rows:
                raise ValueError("evidence inventory row budget exceeded")
            for storage_class, candidate in batch:
                total += 1
                if storage_class != "text":
                    nontext += 1
                elif type(candidate) is str and canonical_evidence_id(candidate) is not None:
                    canonical += 1
                else:
                    other_text += 1
        return EvidenceIdInventory(total, canonical, other_text, nontext)
    except (sqlite3.Error, UnicodeError):
        # Deliberately avoid leaking source IDs, paths, SQL or database contents.
        raise ValueError("evidence inventory unavailable or invalid SQLite schema") from None
    finally:
        if connection is not None:
            connection.close()
