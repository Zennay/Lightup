"""Offline reference contract: remediation evidence must precede verified retest.

This is a pure, deliberately independent acceptance model. It does not authorize
execution, query a target, or validate the production implementation.
"""
from datetime import datetime, timezone
import unittest


def _instant(value):
    if type(value) is not str or not value or len(value) > 40:
        raise ValueError("evidence temporal integrity: invalid timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError("evidence temporal integrity: invalid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("evidence temporal integrity: timezone required")
    if parsed.utcoffset().total_seconds() != 0:
        raise ValueError("evidence temporal integrity: UTC required")
    return parsed.astimezone(timezone.utc)


def validate_lineage(initial, remediation, retest):
    """Return immutable accepted evidence IDs, never an authorization decision."""
    records = (initial, remediation, retest)
    for record in records:
        if type(record) is not dict or set(record) != {"evidence_id", "finding_id", "at"}:
            raise ValueError("evidence temporal integrity: record shape")
        for field in ("evidence_id", "finding_id"):
            value = record[field]
            if type(value) is not str or not value.strip() or len(value) > 128:
                raise ValueError("evidence temporal integrity: invalid identity")
            if value != value.strip():
                raise ValueError("evidence temporal integrity: noncanonical identity")
    if len({r["evidence_id"] for r in records}) != 3:
        raise ValueError("evidence temporal integrity: duplicate evidence")
    if len({r["finding_id"] for r in records}) != 1:
        raise ValueError("evidence temporal integrity: cross-finding evidence")
    times = tuple(_instant(record["at"]) for record in records)
    if not (times[0] < times[1] < times[2]):
        raise ValueError("evidence temporal integrity: nonmonotonic provenance")
    return tuple(record["evidence_id"] for record in records)


class TemporalEvidenceLineageReferenceTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            {"evidence_id": "observation-a", "finding_id": "finding-1", "at": "2026-10-08T10:00:00+00:00"},
            {"evidence_id": "fix-a", "finding_id": "finding-1", "at": "2026-10-08T11:00:00+00:00"},
            {"evidence_id": "retest-a", "finding_id": "finding-1", "at": "2026-10-08T12:00:00+00:00"},
        ]

    def reject(self, field, value, index):
        records = [dict(r) for r in self.rows]
        records[index][field] = value
        snapshot = repr(records)
        with self.assertRaisesRegex(ValueError, "evidence temporal integrity"):
            validate_lineage(*records)
        self.assertEqual(repr(records), snapshot)

    def test_canonical_sequence(self):
        self.assertEqual(validate_lineage(*self.rows), ("observation-a", "fix-a", "retest-a"))

    def test_equal_timestamps_rejected(self):
        self.reject("at", self.rows[0]["at"], 1)

    def test_retest_precedes_fix_rejected(self):
        self.reject("at", "2026-10-08T09:00:00+00:00", 2)

    def test_naive_time_rejected(self):
        self.reject("at", "2026-10-08T11:00:00", 1)

    def test_non_utc_offset_rejected(self):
        self.reject("at", "2026-10-08T13:00:00+02:00", 1)

    def test_invalid_timestamp_rejected(self):
        self.reject("at", "invalid", 1)

    def test_bool_timestamp_rejected(self):
        self.reject("at", True, 1)

    def test_cross_finding_rejected(self):
        self.reject("finding_id", "finding-2", 2)

    def test_duplicate_evidence_rejected(self):
        self.reject("evidence_id", "observation-a", 2)

    def test_noncanonical_identity_rejected(self):
        self.reject("evidence_id", " fix-a ", 1)

    def test_subclassed_identity_rejected(self):
        class StrSubclass(str):
            pass
        self.reject("evidence_id", StrSubclass("fix-a"), 1)

    def test_noncanonical_record_type_rejected(self):
        class DictSubclass(dict):
            pass
        with self.assertRaisesRegex(ValueError, "evidence temporal integrity"):
            validate_lineage(DictSubclass(self.rows[0]), *self.rows[1:])

    def test_timestamp_subclass_rejected(self):
        class StrSubclass(str):
            pass
        self.reject("at", StrSubclass("2026-10-08T11:00:00+00:00"), 1)

    def test_empty_timestamp_rejected(self):
        self.reject("at", "", 1)

    def test_oversized_timestamp_rejected(self):
        self.reject("at", "2" * 41, 1)

    def test_noncanonical_finding_identity_rejected(self):
        self.reject("finding_id", " finding-1", 1)

    def test_same_evidence_id_on_adjacent_steps_rejected(self):
        self.reject("evidence_id", "fix-a", 2)

    def test_retest_equal_to_fix_rejected(self):
        self.reject("at", self.rows[1]["at"], 2)

    def test_canonical_inputs_unchanged(self):
        snapshot = repr(self.rows)
        validate_lineage(*self.rows)
        self.assertEqual(repr(self.rows), snapshot)

    def test_extra_authority_fields_rejected(self):
        rows = [dict(r) for r in self.rows]
        rows[2]["approved"] = True
        with self.assertRaisesRegex(ValueError, "evidence temporal integrity"):
            validate_lineage(*rows)


if __name__ == "__main__":
    unittest.main()
