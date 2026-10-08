"""Offline reference acceptance cases for evidence tombstone integrity.

This intentionally does not import or validate the production evidence store.
"""
import dataclasses
import hashlib
import json
import unittest


@dataclasses.dataclass(frozen=True)
class Receipt:
    tenant: str
    evidence_id: str
    digest: str
    sequence: int
    kind: str
    reason: str = ""
    prior_hash: str = ""


def seal(receipt):
    payload = dataclasses.asdict(receipt)
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def transition(previous, proposed, *, expected_prior_hash):
    """Minimal fail-closed reference policy, NOT a production verifier."""
    if type(previous) is not Receipt or type(proposed) is not Receipt:
        raise ValueError("exact receipt types required")
    for value in (previous.tenant, previous.evidence_id, proposed.tenant, proposed.evidence_id):
        if type(value) is not str or not value or len(value) > 128:
            raise ValueError("invalid identity")
    if proposed.tenant != previous.tenant or proposed.evidence_id != previous.evidence_id:
        raise ValueError("cross-boundary transition")
    if type(proposed.sequence) is not int or proposed.sequence != previous.sequence + 1:
        raise ValueError("nonmonotonic sequence")
    if type(expected_prior_hash) is not str or expected_prior_hash != seal(previous):
        raise ValueError("stale predecessor")
    if proposed.prior_hash != expected_prior_hash:
        raise ValueError("unbound predecessor")
    if type(proposed.digest) is not str or proposed.digest != previous.digest:
        raise ValueError("evidence digest rewritten")
    if previous.kind == "tombstone" or proposed.kind != "tombstone":
        raise ValueError("illegal lifecycle transition")
    if type(proposed.reason) is not str or not proposed.reason.strip() or len(proposed.reason) > 256:
        raise ValueError("tombstone reason missing or oversized")
    return seal(proposed)


class EvidenceTombstoneReferenceTests(unittest.TestCase):
    def setUp(self):
        self.source = Receipt("tenant-a", "ev-17", "a" * 64, 4, "active")
        self.prev = seal(self.source)
        self.deleted = Receipt("tenant-a", "ev-17", "a" * 64, 5, "tombstone", "retention expiration", self.prev)

    def test_valid_tombstone_is_sealed(self):
        self.assertEqual(transition(self.source, self.deleted, expected_prior_hash=self.prev), seal(self.deleted))

    def test_cross_tenant_transition_denied(self):
        with self.assertRaises(ValueError):
            transition(self.source, dataclasses.replace(self.deleted, tenant="tenant-b"), expected_prior_hash=self.prev)

    def test_cross_evidence_transition_denied(self):
        with self.assertRaises(ValueError):
            transition(self.source, dataclasses.replace(self.deleted, evidence_id="ev-18"), expected_prior_hash=self.prev)

    def test_digest_replacement_denied(self):
        with self.assertRaises(ValueError):
            transition(self.source, dataclasses.replace(self.deleted, digest="b" * 64), expected_prior_hash=self.prev)

    def test_missing_reason_denied(self):
        for reason in ("", "  ", None, "x" * 257):
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                transition(self.source, dataclasses.replace(self.deleted, reason=reason), expected_prior_hash=self.prev)

    def test_stale_predecessor_denied(self):
        with self.assertRaises(ValueError):
            transition(self.source, self.deleted, expected_prior_hash="0" * 64)

    def test_unbound_predecessor_denied(self):
        with self.assertRaises(ValueError):
            transition(self.source, dataclasses.replace(self.deleted, prior_hash="0" * 64), expected_prior_hash=self.prev)

    def test_skipped_and_boolean_sequence_denied(self):
        for value in (4, 6, True, "5"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                transition(self.source, dataclasses.replace(self.deleted, sequence=value), expected_prior_hash=self.prev)

    def test_resurrection_and_double_delete_denied(self):
        for kind in ("active", "tombstone"):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                transition(self.deleted, dataclasses.replace(self.deleted, sequence=6, kind=kind, prior_hash=seal(self.deleted)), expected_prior_hash=seal(self.deleted))

    def test_non_tombstone_transition_denied(self):
        with self.assertRaises(ValueError):
            transition(self.source, dataclasses.replace(self.deleted, kind="active"), expected_prior_hash=self.prev)

    def test_subclass_and_noncanonical_identity_denied(self):
        class ForgedReceipt(Receipt):
            pass
        with self.assertRaises(ValueError):
            transition(self.source, ForgedReceipt(**dataclasses.asdict(self.deleted)), expected_prior_hash=self.prev)
        with self.assertRaises(ValueError):
            transition(self.source, dataclasses.replace(self.deleted, evidence_id=""), expected_prior_hash=self.prev)

    def test_original_receipt_not_mutated(self):
        original = dataclasses.asdict(self.source)
        transition(self.source, self.deleted, expected_prior_hash=self.prev)
        self.assertEqual(dataclasses.asdict(self.source), original)


if __name__ == "__main__":
    unittest.main()
