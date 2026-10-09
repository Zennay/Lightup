"""Offline lexical acceptance reference for LightUp's uuid4 evidence IDs.

Source observation: src/lightup/state.py add_evidence() issues str(uuid4()).
These tests do not establish issuer provenance, tenant isolation or read authority.
"""
import hashlib
import re
import tempfile
import unittest
from pathlib import Path
from uuid import UUID, uuid4

_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    re.ASCII,
)


def canonical_evidence_id(value):
    if type(value) is not str or len(value) != 36 or _PATTERN.fullmatch(value) is None:
        raise ValueError("noncanonical evidence identifier")
    return value


class EvidenceIdentifierReferenceTests(unittest.TestCase):
    VALID = "12345678-1234-4234-8234-123456789abc"

    def test_rejected_selector_never_reaches_reference_lookup(self):
        class SpyStore:
            def __init__(self):
                self.lookups = []

            def get_evidence(self, identifier):
                self.lookups.append(identifier)
                return identifier

        def reference_lookup(store, identifier):
            # Proposed admission order only; not wired into production.
            return store.get_evidence(canonical_evidence_id(identifier))

        store = SpyStore()
        for invalid in (self.VALID.upper(), self.VALID.replace("-", ""),
                        None, True, " " + self.VALID):
            with self.subTest(invalid=repr(invalid)):
                with self.assertRaisesRegex(ValueError, "noncanonical"):
                    reference_lookup(store, invalid)
                self.assertEqual(store.lookups, [])
        self.assertEqual(reference_lookup(store, self.VALID), self.VALID)
        self.assertEqual(store.lookups, [self.VALID])

    def test_canonical_uuid4_accepted_without_normalization(self):
        self.assertEqual(canonical_evidence_id(self.VALID), self.VALID)

    def test_offline_state_store_issued_id_and_digest_are_separate(self):
        # Real production issuer; temporary local SQLite only, plan-only run.
        from lightup.state import StateStore

        payload = b"offline evidence identifier compatibility fixture"
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "reference.db")
            run_id = store.create_run(target="local-fixture", activation_mode="plan_only")
            evidence_id = store.add_evidence(
                run_id=run_id, capability_id="fixture", kind="reference",
                source="offline", payload=payload,
            )
            self.assertEqual(canonical_evidence_id(evidence_id), evidence_id)
            record = store.get_evidence(evidence_id)
            self.assertEqual(record.evidence_id, evidence_id)
            self.assertEqual(record.run_id, run_id)
            self.assertEqual(record.sha256, hashlib.sha256(payload).hexdigest())
            self.assertNotEqual(record.sha256, evidence_id)

    def test_temporary_store_rejected_alias_does_not_change_evidence_row(self):
        from lightup.state import StateStore

        payload = b"offline row immutability acceptance"
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "immutability.db")
            run_id = store.create_run(target="local-fixture", activation_mode="plan_only")
            identifier = store.add_evidence(
                run_id=run_id, capability_id="fixture", kind="reference",
                source="offline", payload=payload,
            )
            with store.connect() as con:
                before = tuple(con.execute(
                    "SELECT evidence_id,run_id,capability_id,kind,source,sha256,"
                    "metadata_json,created_at FROM evidence WHERE evidence_id=?",
                    (identifier,),
                ).fetchone())
            alias = identifier.upper()
            self.assertRejected(alias)
            with store.connect() as con:
                after = tuple(con.execute(
                    "SELECT evidence_id,run_id,capability_id,kind,source,sha256,"
                    "metadata_json,created_at FROM evidence WHERE evidence_id=?",
                    (identifier,),
                ).fetchone())
                count = con.execute("SELECT count(*) FROM evidence").fetchone()[0]
            self.assertEqual(before, after)
            self.assertEqual(count, 1)

    def test_issuer_uuid_identity_is_stable_across_reopen(self):
        from lightup.state import StateStore

        payload = b"offline reopen identity fixture"
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "reopen.db"
            store = StateStore(database)
            run_id = store.create_run(target="local-fixture", activation_mode="plan_only")
            evidence_id = store.add_evidence(
                run_id=run_id, capability_id="fixture", kind="reference",
                source="offline", payload=payload,
            )
            reopened = StateStore(database)
            record = reopened.get_evidence(evidence_id)
            self.assertEqual(record.evidence_id, canonical_evidence_id(evidence_id))
            self.assertEqual(record.sha256, hashlib.sha256(payload).hexdigest())
            self.assertEqual(record.run_id, run_id)

    def test_offline_issued_ids_distinguish_runs_and_preserve_row_binding(self):
        from lightup.state import StateStore

        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "two-runs.db")
            first_run = store.create_run(target="fixture-one", activation_mode="plan_only")
            second_run = store.create_run(target="fixture-two", activation_mode="plan_only")
            first_id = store.add_evidence(
                run_id=first_run, capability_id="fixture", kind="reference",
                source="offline", payload=b"first",
            )
            second_id = store.add_evidence(
                run_id=second_run, capability_id="fixture", kind="reference",
                source="offline", payload=b"second",
            )
            self.assertNotEqual(first_id, second_id)
            self.assertEqual(canonical_evidence_id(first_id), first_id)
            self.assertEqual(canonical_evidence_id(second_id), second_id)
            self.assertEqual(store.get_evidence(first_id).run_id, first_run)
            self.assertEqual(store.get_evidence(second_id).run_id, second_run)
            self.assertEqual(store.get_evidence(first_id).sha256,
                             hashlib.sha256(b"first").hexdigest())
            self.assertEqual(store.get_evidence(second_id).sha256,
                             hashlib.sha256(b"second").hexdigest())

    def test_missing_canonical_uuid_does_not_create_evidence(self):
        from lightup.state import StateStore

        missing_id = "12345678-1234-4234-8234-123456789abc"
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "missing.db")
            self.assertEqual(canonical_evidence_id(missing_id), missing_id)
            with self.assertRaises((KeyError, ValueError)):
                store.get_evidence(missing_id)
            with store.connect() as con:
                count = con.execute("SELECT count(*) FROM evidence").fetchone()[0]
            self.assertEqual(count, 0)

    def test_duplicate_payloads_have_distinct_issued_ids_but_same_digest(self):
        from lightup.state import StateStore

        payload = b"identical offline fixture bytes"
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "duplicate-payload.db")
            run_id = store.create_run(target="local-fixture", activation_mode="plan_only")
            ids = [
                store.add_evidence(
                    run_id=run_id, capability_id="fixture", kind="reference",
                    source="offline", payload=payload,
                )
                for _ in range(2)
            ]
            self.assertNotEqual(ids[0], ids[1])
            records = [store.get_evidence(identifier) for identifier in ids]
            expected_digest = hashlib.sha256(payload).hexdigest()
            self.assertEqual([record.sha256 for record in records],
                             [expected_digest, expected_digest])
            self.assertEqual([record.evidence_id for record in records], ids)

    def test_actual_uuid4_issuer_samples_roundtrip(self):
        # Standard-library issuer path used by StateStore.add_evidence.
        for _ in range(32):
            identifier = str(uuid4())
            self.assertEqual(canonical_evidence_id(identifier), identifier)

    def test_invalid_uuid_version_four_nibble_is_rejected(self):
        for nibble in "012356789abcdef":
            self.assertRejected(self.VALID[:14] + nibble + self.VALID[15:])

    def test_invalid_variant_nibble_is_rejected(self):
        for nibble in "01234567cdef":
            self.assertRejected(self.VALID[:19] + nibble + self.VALID[20:])

    def test_distinct_canonical_ids_remain_distinct(self):
        other = "12345678-1234-4234-8234-123456789abd"
        self.assertNotEqual(canonical_evidence_id(self.VALID),
                            canonical_evidence_id(other))

    def test_standard_uuid_parser_is_not_a_canonicality_gate(self):
        # uuid.UUID accepts aliases that the strict reference must deny.
        alias = self.VALID.upper()
        self.assertEqual(str(UUID(alias)), self.VALID)
        self.assertRejected(alias)
        compact = self.VALID.replace("-", "")
        self.assertEqual(str(UUID(compact)), self.VALID)
        self.assertRejected(compact)

    def test_nil_and_max_uuid_are_rejected(self):
        self.assertRejected(str(UUID(int=0)))
        self.assertRejected(str(UUID(int=(1 << 128) - 1)))

    def test_uppercase_uuid_alias_is_rejected(self):
        self.assertRejected(self.VALID.upper())

    def test_uuid_urn_braces_and_compact_aliases_rejected(self):
        for value in ("urn:uuid:" + self.VALID, "{" + self.VALID + "}",
                      self.VALID.replace("-", "")):
            self.assertRejected(value)

    def test_other_uuid_versions_rejected(self):
        for version in ("1", "3", "5", "7"):
            self.assertRejected(self.VALID[:14] + version + self.VALID[15:])

    def test_non_rfc4122_variant_rejected(self):
        for variant in ("0", "4", "7", "c", "f"):
            self.assertRejected(self.VALID[:19] + variant + self.VALID[20:])

    def test_unicode_confusables_rejected(self):
        self.assertRejected(self.VALID.replace("a", "а"))
        self.assertRejected(self.VALID.replace("1", "１"))

    def test_whitespace_and_controls_rejected(self):
        for value in (" " + self.VALID, self.VALID + "\n",
                      self.VALID + "\x00", self.VALID + "\u2028"):
            self.assertRejected(value)

    def test_wrong_length_and_separators_rejected(self):
        for value in (self.VALID[:-1], self.VALID + "0",
                      self.VALID.replace("-", "_"),
                      self.VALID.replace("-", "/")):
            self.assertRejected(value)

    def test_exact_builtin_string_required(self):
        class StrAlias(str):
            pass
        for value in (None, True, 42, self.VALID.encode(), StrAlias(self.VALID)):
            self.assertRejected(value)

    def test_rejected_input_not_mutated(self):
        value = self.VALID.upper()
        self.assertRejected(value)
        self.assertEqual(value, self.VALID.upper())

    def assertRejected(self, value):
        with self.subTest(value=repr(value)):
            with self.assertRaises(ValueError) as caught:
                canonical_evidence_id(value)
            self.assertEqual(str(caught.exception),
                             "noncanonical evidence identifier")


if __name__ == "__main__":
    unittest.main()
