"""Offline reference-only temporal authorization contract (no production imports).

This oracle is deliberately not an authorization engine or proof of dispatch safety.
All fixtures are synthetic; tests perform no I/O, network or subprocess actions.
"""
import unittest


def eligible(grant, request, now):
    """Reference eligibility only; NOT trusted approval or executable authority."""
    if type(now) is not int or now < 0:
        return False
    if type(grant) is not dict or type(request) is not dict:
        return False
    required_grant = {"tenant", "engagement", "grant_id", "issued_at", "not_before", "expires_at", "revoked"}
    required_request = {"tenant", "engagement", "grant_id"}
    if set(grant) != required_grant or set(request) != required_request:
        return False
    for name in ("tenant", "engagement", "grant_id"):
        if type(grant[name]) is not str or not grant[name] or type(request[name]) is not str:
            return False
        if grant[name] != request[name]:
            return False
    if type(grant["revoked"]) is not bool or grant["revoked"]:
        return False
    for name in ("issued_at", "not_before", "expires_at"):
        if type(grant[name]) is not int or grant[name] < 0:
            return False
    issued, start, end = (grant[key] for key in ("issued_at", "not_before", "expires_at"))
    return issued <= start < end and start <= now < end


BASE = {"tenant": "tenant-A", "engagement": "eng-1", "grant_id": "grant-1",
        "issued_at": 100, "not_before": 110, "expires_at": 120, "revoked": False}
REQUEST = {"tenant": "tenant-A", "engagement": "eng-1", "grant_id": "grant-1"}


class TemporalBoundaryContract(unittest.TestCase):
    def assert_denied(self, **overrides):
        self.assertFalse(eligible(dict(BASE, **overrides), REQUEST, 115))

    def test_inclusive_not_before_exclusive_expiry(self):
        self.assertFalse(eligible(BASE, REQUEST, 109))
        self.assertTrue(eligible(BASE, REQUEST, 110))
        self.assertTrue(eligible(BASE, REQUEST, 119))
        self.assertFalse(eligible(BASE, REQUEST, 120))
        self.assertFalse(eligible(BASE, REQUEST, 121))

    def test_reversed_and_zero_length_intervals_deny(self):
        for start, end in ((120, 120), (121, 120), (99, 120)):
            with self.subTest(start=start, end=end):
                self.assert_denied(not_before=start, expires_at=end)

    def test_invalid_epoch_types_deny_including_bool(self):
        for value in (True, False, 1.5, "115", None, -1, [], {}):
            for key in ("issued_at", "not_before", "expires_at"):
                with self.subTest(key=key, value=repr(value)):
                    self.assert_denied(**{key: value})
            with self.subTest(now=repr(value)):
                self.assertFalse(eligible(BASE, REQUEST, value))

    def test_revoked_and_non_boolean_revocation_deny(self):
        for value in (True, 1, 0, None, "false", []):
            with self.subTest(value=repr(value)):
                self.assert_denied(revoked=value)

    def test_exact_identity_binding_without_coercion(self):
        for field, other in (("tenant", "tenant-B"), ("engagement", "eng-2"), ("grant_id", "grant-2")):
            with self.subTest(field=field):
                self.assertFalse(eligible(BASE, dict(REQUEST, **{field: other}), 115))
                self.assertFalse(eligible(dict(BASE, **{field: other}), REQUEST, 115))
                self.assertFalse(eligible(dict(BASE, **{field: 1}), REQUEST, 115))
                self.assertFalse(eligible(BASE, dict(REQUEST, **{field: 1}), 115))

    def test_unexpected_and_missing_fields_deny(self):
        for field in BASE:
            modified = dict(BASE)
            del modified[field]
            self.assertFalse(eligible(modified, REQUEST, 115), field)
        for field in REQUEST:
            modified = dict(REQUEST)
            del modified[field]
            self.assertFalse(eligible(BASE, modified, 115), field)
        self.assertFalse(eligible(dict(BASE, approval="fake"), REQUEST, 115))
        self.assertFalse(eligible(BASE, dict(REQUEST, mode="TARGET_ACTIVE"), 115))

    def test_time_rollback_must_not_reanimate_expired_authority(self):
        """A stateless clock oracle alone cannot guarantee rollback resistance."""
        self.assertFalse(eligible(BASE, REQUEST, 120))
        self.assertTrue(eligible(BASE, REQUEST, 119))  # documents the hazard
        # Production must use trusted monotonic/durable last-observed time or deny rollback.

    def test_now_is_not_implicit_host_clock(self):
        self.assertFalse(eligible(BASE, REQUEST, None))
        self.assertFalse(eligible(BASE, REQUEST, True))
        self.assertFalse(eligible(BASE, REQUEST, "115"))


if __name__ == "__main__":
    unittest.main()
