"""Disposable SQLite + local byte fixtures for optional evidence integrity (#1075)."""
from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from lightup.evidence_payload_integrity_reference import (
    verify_scoped_evidence_payload_reference as verify,
)
from lightup.state import StateStore


class BytesSubclass(bytes):
    pass


class EvidencePayloadIntegrityReferenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="lightup-payload-integrity-lab-")
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "synthetic.sqlite3"
        self.store = StateStore(self.path)
        self.run_id = self.store.create_run(
            "synthetic-only", activation_mode="plan_only"
        )
        self.capability = "offline-capability"
        self.payload = b"synthetic bytes: no external target or customer data"
        self.evidence_id = self.store.add_evidence(
            self.run_id, self.capability, "fixture", "unit",
            self.payload, metadata={"synthetic": "yes"}
        )
        self.events = []

    def _verify(self, payload=None, *, evidence_id=None, checker=None, max_bytes=8*1024*1024):
        return verify(
            self.store,
            self.evidence_id if evidence_id is None else evidence_id,
            self.payload if payload is None else payload,
            trusted_run_id=self.run_id,
            trusted_capability_id=self.capability,
            check_current_permission=checker or (
                lambda run, capability, evidence: self.events.append(
                    (run, capability, evidence)
                ) or True
            ),
            max_payload_bytes=max_bytes,
        )

    def _durable_rows(self):
        with self.store.connect() as connection:
            return tuple(
                tuple(row) for row in connection.execute(
                    "SELECT evidence_id,run_id,capability_id,kind,source,sha256,"
                    "metadata_json,created_at FROM evidence ORDER BY evidence_id"
                )
            )

    def test_real_issuer_payload_digest_matches_and_three_checks_occur(self):
        before = self._durable_rows()
        record = self._verify()
        self.assertEqual(record.evidence_id, self.evidence_id)
        self.assertEqual(record.sha256, hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(
            self.events, [(self.run_id, self.capability, self.evidence_id)] * 3
        )
        self.assertEqual(self._durable_rows(), before)
        self.assertNotIn(self.payload.decode(), repr(record))

    def test_empty_bytes_are_a_valid_issuer_payload(self):
        eid = self.store.add_evidence(
            self.run_id, self.capability, "fixture", "unit", b""
        )
        record = verify(
            self.store, eid, b"",
            trusted_run_id=self.run_id,
            trusted_capability_id=self.capability,
            check_current_permission=lambda *_: True,
        )
        self.assertEqual(record.sha256, hashlib.sha256(b"").hexdigest())

    def test_payload_subclasses_and_mutable_bytes_are_denied_before_any_read(self):
        invalid = (BytesSubclass(self.payload), bytearray(self.payload),
                   memoryview(self.payload), "not bytes", 7, [], True)
        before = self._durable_rows()
        for candidate in invalid:
            with self.subTest(t=type(candidate).__name__):
                with patch.object(self.store, "get_evidence") as reader:
                    with self.assertRaisesRegex(ValueError, "bounded evidence payload"):
                        self._verify(
                            candidate,
                            checker=lambda *_: self.fail("grant checked before byte preflight"),
                        )
                    reader.assert_not_called()
        self.assertEqual(self._durable_rows(), before)

    def test_explicit_none_payload_is_denied_without_store_access(self):
        with patch.object(self.store, "get_evidence") as reader:
            with self.assertRaisesRegex(ValueError, "bounded evidence payload"):
                verify(
                    self.store, self.evidence_id, None,
                    trusted_run_id=self.run_id,
                    trusted_capability_id=self.capability,
                    check_current_permission=lambda *_: True,
                )
            reader.assert_not_called()

    def test_invalid_or_boolean_payload_budget_is_denied_pre_read(self):
        for budget in (False, True, 0, -1, 8*1024*1024+1, "20", 1.5):
            with self.subTest(budget=budget):
                with patch.object(self.store, "get_evidence") as reader:
                    with self.assertRaisesRegex(ValueError, "payload budget"):
                        self._verify(max_bytes=budget)
                    reader.assert_not_called()

    def test_exact_size_cap_and_one_byte_over_are_respected(self):
        record = self._verify(max_bytes=len(self.payload))
        self.assertEqual(record.evidence_id, self.evidence_id)
        with patch.object(self.store, "get_evidence") as reader:
            with self.assertRaisesRegex(ValueError, "bounded evidence payload"):
                self._verify(max_bytes=len(self.payload)-1)
            reader.assert_not_called()

    def test_sha_mismatch_is_generic_and_never_modifies_evidence(self):
        before = self._durable_rows()
        with self.assertRaisesRegex(ValueError, "integrity unavailable") as caught:
            self._verify(self.payload + b"tampered")
        self.assertEqual(len(self.events), 2)  # No third success callback
        self.assertNotIn("tampered", str(caught.exception))
        self.assertNotIn(self.evidence_id, str(caught.exception))
        self.assertEqual(self._durable_rows(), before)

    def test_corrupt_persisted_digest_shapes_are_denied(self):
        original = hashlib.sha256(self.payload).hexdigest()
        invalid = ("Q"*64, original.upper(), original + "0", "123",
                   "f"*63+"é", sqlite3.Binary(b"\x01"*32))
        for digest in invalid:
            with self.subTest(digest=repr(digest)[:30]):
                with self.store.connect() as db:
                    db.execute(
                        "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                        (digest, self.evidence_id),
                    )
                with self.assertRaisesRegex(ValueError, "integrity unavailable"):
                    self._verify()
                with self.store.connect() as db:
                    db.execute(
                        "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                        (original, self.evidence_id),
                    )
        self.assertEqual(self.store.get_evidence(self.evidence_id).sha256, original)

    def test_well_formed_but_wrong_persisted_digest_is_refused(self):
        before = self._durable_rows()
        replacement = hashlib.sha256(b"other-synthetic-content").hexdigest()
        with self.store.connect() as db:
            db.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, self.evidence_id),
            )
        with self.assertRaisesRegex(ValueError, "integrity unavailable"):
            self._verify()
        with self.store.connect() as db:
            db.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (before[0][5], self.evidence_id),
            )
        self.assertEqual(before, self._durable_rows())

    def test_noncanonical_evidence_selection_cannot_reach_database(self):
        with patch.object(self.store, "get_evidence") as reader:
            with self.assertRaisesRegex(ValueError, "noncanonical"):
                self._verify(
                    evidence_id=self.evidence_id.upper(),
                    checker=lambda *_: self.fail("lookup happened"),
                )
            reader.assert_not_called()

    def test_first_permission_denial_prevents_byte_digest_and_database_access(self):
        with patch.object(self.store, "get_evidence") as reader:
            with patch("lightup.evidence_payload_integrity_reference.hashlib.sha256") as sha:
                with self.assertRaises(PermissionError):
                    self._verify(checker=lambda *_: False)
                reader.assert_not_called()
                sha.assert_not_called()

    def test_second_permission_denial_never_hashes_payload(self):
        calls = []
        with patch("lightup.evidence_payload_integrity_reference.hashlib.sha256") as sha:
            with self.assertRaises(PermissionError):
                self._verify(checker=lambda *_: calls.append(1) or len(calls) == 1)
            sha.assert_not_called()
        self.assertEqual(calls, [1, 1])

    def test_revoke_after_hash_refuses_return(self):
        calls = []
        before = self._durable_rows()
        with self.assertRaisesRegex(PermissionError, "lookup denied"):
            self._verify(checker=lambda *_: calls.append(1) or len(calls) < 3)
        self.assertEqual(calls, [1, 1, 1])
        self.assertEqual(self._durable_rows(), before)

    def test_third_permission_exception_never_exposes_secret_in_context(self):
        calls = []
        def checker(*_):
            calls.append(1)
            if len(calls) == 3:
                raise RuntimeError("PRIVATE_CHECKER_TOKEN")
            return True
        with self.assertRaises(PermissionError) as error:
            self._verify(checker=checker)
        self.assertEqual(len(calls), 3)
        self.assertNotIn("PRIVATE_CHECKER_TOKEN", str(error.exception))
        self.assertIsNone(error.exception.__cause__)
        self.assertIsNone(error.exception.__context__)

    def test_unknown_uuid_does_not_reveal_existence_details(self):
        unknown = str(uuid4())
        while unknown == self.evidence_id:
            unknown = str(uuid4())
        with self.assertRaises(LookupError) as error:
            self._verify(evidence_id=unknown)
        self.assertNotIn(unknown, str(error.exception))
        self.assertIsNone(error.exception.__context__)


if __name__ == "__main__":
    unittest.main()
