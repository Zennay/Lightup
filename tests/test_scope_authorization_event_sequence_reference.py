"""Offline reference only: contiguous authorization event sequence is necessary, never authority."""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class Event:
    tenant: str
    grant: str
    sequence: int
    kind: str


def contiguous(events, tenant, grant, starting_sequence):
    """Reject gaps, duplicates, reordering, identity swaps and malformed input."""
    if type(events) is not tuple or type(tenant) is not str or not tenant or type(grant) is not str or not grant:
        return False
    if type(starting_sequence) is not int or starting_sequence < 0:
        return False
    if not events:
        return False
    for offset, event in enumerate(events):
        if type(event) is not Event:
            return False
        if (type(event.tenant) is not str or type(event.grant) is not str
                or event.tenant != tenant or event.grant != grant
                or type(event.sequence) is not int
                or event.sequence != starting_sequence + offset + 1
                or type(event.kind) is not str
                or event.kind not in ("issued", "approved", "revoked", "expired")):
            return False
    return True


class SequenceReferenceTests(unittest.TestCase):
    def setUp(self):
        self.events = (Event("tenant-a", "grant-a", 11, "issued"),
                       Event("tenant-a", "grant-a", 12, "approved"))

    def test_contiguous_reference_shape(self):
        self.assertTrue(contiguous(self.events, "tenant-a", "grant-a", 10))

    def test_gap_denied(self):
        self.assertFalse(contiguous((self.events[0], Event("tenant-a", "grant-a", 13, "approved")), "tenant-a", "grant-a", 10))

    def test_duplicate_denied(self):
        self.assertFalse(contiguous((self.events[0], self.events[0]), "tenant-a", "grant-a", 10))

    def test_reorder_denied(self):
        self.assertFalse(contiguous(tuple(reversed(self.events)), "tenant-a", "grant-a", 10))

    def test_wrong_tenant_denied(self):
        self.assertFalse(contiguous((Event("tenant-b", "grant-a", 11, "issued"), self.events[1]), "tenant-a", "grant-a", 10))

    def test_wrong_grant_denied(self):
        self.assertFalse(contiguous((Event("tenant-a", "grant-b", 11, "issued"), self.events[1]), "tenant-a", "grant-a", 10))

    def test_bool_sequence_denied(self):
        self.assertFalse(contiguous((Event("tenant-a", "grant-a", True, "issued"),), "tenant-a", "grant-a", 0))
        self.assertFalse(contiguous(self.events, "tenant-a", "grant-a", True))

    def test_unknown_kind_denied(self):
        self.assertFalse(contiguous((Event("tenant-a", "grant-a", 11, "secret_override"),), "tenant-a", "grant-a", 10))

    def test_subclass_denied(self):
        class Forged(Event):
            pass
        self.assertFalse(contiguous((Forged("tenant-a", "grant-a", 11, "issued"),), "tenant-a", "grant-a", 10))

    def test_container_and_empty_denied(self):
        self.assertFalse(contiguous(list(self.events), "tenant-a", "grant-a", 10))
        self.assertFalse(contiguous((), "tenant-a", "grant-a", 10))

    def test_bad_identity_and_start_denied(self):
        self.assertFalse(contiguous(self.events, "", "grant-a", 10))
        self.assertFalse(contiguous(self.events, "tenant-a", "", 10))
        self.assertFalse(contiguous(self.events, "tenant-a", "grant-a", -1))

    def test_input_not_mutated(self):
        snapshot = repr(self.events)
        contiguous(self.events, "tenant-a", "grant-a", 10)
        self.assertEqual(repr(self.events), snapshot)


if __name__ == "__main__":
    unittest.main()
