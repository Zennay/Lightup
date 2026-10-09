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
    if type(current) is not Consent or type(current.grant_id) is not str or not current.grant_id:
        raise ValueError("invalid current grant")
    if type(current.revision) is not int or current.revision < 0:
        raise ValueError("invalid current revision")
    if type(current.withdrawn) is not bool:
        raise ValueError("invalid withdrawal state")
    if event_grant_id != current.grant_id:
        raise ValueError("wrong grant")
    if event_revision <= current.revision:
        raise ValueError("stale or replayed withdrawal")
    return replace(current, revision=event_revision, withdrawn=True)


def decide_offline(current: Consent, *, issuer_verified: bool, within_scope: bool) -> bool:
    """Illustrative deny-only check, never a grant of runtime permission."""
    return (type(current) is Consent
            and type(current.grant_id) is str and bool(current.grant_id)
            and type(current.revision) is int and current.revision >= 0
            and type(current.withdrawn) is bool
            and type(issuer_verified) is bool and issuer_verified
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

    def test_malformed_persisted_state_fails_closed(self):
        invalid = (
            Consent("grant-A", True, False),
            Consent("grant-A", -1, False),
            Consent("grant-A", 4, 0),
            Consent("grant-A", 4, "false"),
            Consent("", 4, False),
            Consent(b"grant-A", 4, False),
        )
        for item in invalid:
            with self.subTest(item=item):
                self.assertFalse(decide_offline(item, issuer_verified=True, within_scope=True))
                with self.assertRaises(ValueError):
                    apply_withdrawal(item, "grant-A", 5)

    def test_positive_unwithdrawn_control_is_only_shape_check(self):
        self.assertTrue(decide_offline(self.grant, issuer_verified=True, within_scope=True))
        self.assertFalse(decide_offline(self.grant, issuer_verified=False, within_scope=True))
        self.assertFalse(decide_offline(self.grant, issuer_verified=True, within_scope=False))

    def test_stale_events_do_not_modify_live_snapshot(self):
        live = apply_withdrawal(self.grant, "grant-A", 8)
        for revision in (5, 6, 7, 8):
            with self.subTest(revision=revision):
                with self.assertRaises(ValueError):
                    apply_withdrawal(live, "grant-A", revision)
                self.assertEqual(live, Consent("grant-A", 8, True))

    def test_interleaved_unrelated_grant_cannot_mutate_authority(self):
        a = apply_withdrawal(self.grant, "grant-A", 5)
        b = Consent("grant-B", 9)
        with self.assertRaises(ValueError):
            apply_withdrawal(b, "grant-A", 10)
        self.assertEqual(b, Consent("grant-B", 9))
        self.assertFalse(decide_offline(a, issuer_verified=True, within_scope=True))

    def test_malformed_boolean_inputs_not_truthy_authority(self):
        for issuer, scope in ((1, True), (True, 1), ("yes", True), (True, "yes")):
            self.assertFalse(decide_offline(self.grant, issuer_verified=issuer, within_scope=scope))


if __name__ == "__main__":
    unittest.main()
