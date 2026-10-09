"""Offline consent withdrawal state-machine reference; not an execution authorization gate."""
import unittest
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Consent:
    grant_id: str
    revision: int
    withdrawn: bool = False


def apply_withdrawal(current: Consent, event_grant_id: object, event_revision: object) -> Consent:
    """Only an exact, newer withdrawal may change state; withdrawal is irreversible."""
    if type(event_grant_id) is not str or not event_grant_id:
        raise ValueError("noncanonical grant identifier")
    if type(event_revision) is not int or event_revision < 1:
        raise ValueError("noncanonical revision")
    if event_grant_id != current.grant_id:
        raise ValueError("wrong grant")
    if event_revision <= current.revision:
        raise ValueError("stale or replayed withdrawal")
    return replace(current, revision=event_revision, withdrawn=True)


def decide_offline(current: Consent, *, issuer_verified: bool, within_scope: bool) -> bool:
    """Illustrative deny-only check, never a grant of runtime permission."""
    return (type(issuer_verified) is bool and issuer_verified
            and type(within_scope) is bool and within_scope
            and not current.withdrawn)


class ConsentWithdrawalReferenceTests(unittest.TestCase):
    def setUp(self):
        self.grant = Consent("grant-A", 4)

    def test_withdrawal_denies_even_with_other_positive_inputs(self):
        withdrawn = apply_withdrawal(self.grant, "grant-A", 5)
        self.assertFalse(decide_offline(withdrawn, issuer_verified=True, within_scope=True))
        self.assertEqual(self.grant, Consent("grant-A", 4))  # immutable original

    def test_replay_and_stale_versions_fail_closed(self):
        for revision in (0, 3, 4, True, 4.0, "5", None):
            with self.subTest(revision=revision):
                with self.assertRaises(ValueError):
                    apply_withdrawal(self.grant, "grant-A", revision)

    def test_wrong_grant_and_identifier_type_fail(self):
        for identifier in ("grant-B", "", None, b"grant-A"):
            with self.subTest(identifier=identifier):
                with self.assertRaises(ValueError):
                    apply_withdrawal(self.grant, identifier, 5)

    def test_newer_event_does_not_reactivate_withdrawn_grant(self):
        withdrawn = apply_withdrawal(self.grant, "grant-A", 5)
        again = apply_withdrawal(withdrawn, "grant-A", 6)
        self.assertTrue(again.withdrawn)
        self.assertFalse(decide_offline(again, issuer_verified=True, within_scope=True))

    def test_malformed_boolean_inputs_not_truthy_authority(self):
        for issuer, scope in ((1, True), (True, 1), ("yes", True), (True, "yes")):
            self.assertFalse(decide_offline(self.grant, issuer_verified=issuer, within_scope=scope))


if __name__ == "__main__":
    unittest.main()
