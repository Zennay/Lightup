"""Isolated, offline SQLite evidence-ID admission acceptance for issue #1075.

No installed read-path changes: `checked_lookup` is a test-local non-authorizing
adapter. A syntactically valid UUID is NOT a tenant/grant/issuer decision.
"""
from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from lightup.evidence_id_admission import canonical_evidence_id
from lightup.state import StateStore


class StrSubclass(str):
    pass


class CountingLookup:
    """Record when a guarded request actually reaches the real SQLite reader."""

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self.lookups: list[str] = []

    def get_evidence(self, evidence_id: str):
        self.lookups.append(evidence_id)
        return self.store.get_evidence(evidence_id)


def checked_lookup(store: CountingLookup, identifier: object):
    """Test-only ordering reference; not installed and not tenant-authorizing."""
    admitted = canonical_evidence_id(identifier)
    if admitted is None:
        raise ValueError("noncanonical evidence identifier")
    return store.get_evidence(admitted)


class EvidenceUuid4RealSqliteAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="lightup-evidence-lab-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "evidence.sqlite3"
        self.store = StateStore(self.path)
        self.run_id = self.store.create_run(
            target="synthetic-lab-only",
            activation_mode="plan_only",
        )
        self.payload = b"offline synthetic evidence: no target request"
        self.evidence_id = self.store.add_evidence(
            run_id=self.run_id,
            capability_id="synthetic-header-review",
            kind="test-fixture",
            source="disposable-sqlite",
            payload=self.payload,
            metadata={"source": "offline-only"},
        )

    def _snapshot(self):
        with self.store.connect() as connection:
            return [
                tuple(row) for row in connection.execute(
                    "SELECT evidence_id, run_id, capability_id, kind, source, "
                    "sha256, metadata_json, created_at FROM evidence "
                    "ORDER BY evidence_id"
                ).fetchall()
            ]

    def test_real_issuer_record_retains_identity_digest_and_metadata_after_reopen(self):
        lookup = CountingLookup(self.store)
        record = checked_lookup(lookup, self.evidence_id)
        self.assertEqual(record.evidence_id, self.evidence_id)
        self.assertEqual(record.run_id, self.run_id)
        self.assertEqual(record.sha256, hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(record.metadata, (("source", "offline-only"),))
        self.assertEqual(lookup.lookups, [self.evidence_id])
        reopened = StateStore(self.path)
        self.assertEqual(reopened.get_evidence(self.evidence_id), record)

    def test_rejected_aliases_and_polymorphic_inputs_never_reach_sqlite_reader(self):
        lookup = CountingLookup(self.store)
        before = self._snapshot()
        issued = self.evidence_id
        malformed = (
            None, True, False, 0, 3.14, b"uuid", {}, [],
            StrSubclass(issued),
            issued.upper(), issued.replace("-", ""),
            "urn:uuid:" + issued, "{" + issued + "}",
            " " + issued, issued + " ", issued + "\n",
            issued + "\x00", issued[:8] + "_" + issued[9:],
            "12345678-1234-1234-8234-123456789abc",  # wrong version
            "12345678-1234-4234-0234-123456789abc",  # wrong variant
            issued[:-1], issued + "0", issued.replace("-", "\u2010"),
        )
        for candidate in malformed:
            with self.subTest(candidate=repr(candidate)):
                with self.assertRaisesRegex(ValueError, "noncanonical evidence identifier"):
                    checked_lookup(lookup, candidate)
        self.assertEqual(lookup.lookups, [])
        self.assertEqual(self._snapshot(), before)
        self.assertEqual(StateStore(self.path).get_evidence(issued).evidence_id, issued)

    def test_canonical_but_unknown_id_is_not_promoted_to_evidence_or_authority(self):
        lookup = CountingLookup(self.store)
        missing = str(uuid4())
        while missing == self.evidence_id:
            missing = str(uuid4())
        before = self._snapshot()
        self.assertEqual(canonical_evidence_id(missing), missing)
        with self.assertRaises(KeyError):
            checked_lookup(lookup, missing)
        self.assertEqual(lookup.lookups, [missing])
        self.assertEqual(self._snapshot(), before)

    def test_legacy_noncanonical_persisted_identifier_is_not_silently_repaired(self):
        # Historical incompatibility demonstration in a disposable database.
        # This intentionally does NOT modify the installed StateStore reader.
        historical = "historical-evidence-id"
        with self.store.connect() as connection:
            connection.execute(
                "UPDATE evidence SET evidence_id=? WHERE evidence_id=?",
                (historical, self.evidence_id),
            )
        before = self._snapshot()
        self.assertEqual(self.store.get_evidence(historical).evidence_id, historical)
        lookup = CountingLookup(self.store)
        with self.assertRaisesRegex(ValueError, "noncanonical evidence identifier"):
            checked_lookup(lookup, historical)
        self.assertEqual(lookup.lookups, [])
        self.assertEqual(self._snapshot(), before)
        self.assertEqual(StateStore(self.path).get_evidence(historical).evidence_id, historical)

    def test_two_distinct_issued_records_remain_independent(self):
        second_id = self.store.add_evidence(
            run_id=self.run_id,
            capability_id="synthetic-header-review",
            kind="test-fixture",
            source="disposable-sqlite",
            payload=b"second synthetic",
        )
        lookup = CountingLookup(self.store)
        first = checked_lookup(lookup, self.evidence_id)
        second = checked_lookup(lookup, second_id)
        self.assertNotEqual(first.evidence_id, second.evidence_id)
        self.assertEqual(lookup.lookups, [self.evidence_id, second_id])
        self.assertEqual(len(self._snapshot()), 2)


if __name__ == "__main__":
    unittest.main()
