"""Offline reference: Accept-Encoding is transport preference, never authorization.

This intentionally synthetic predicate is not production grant validation.
No network, subprocesses, imports from production executors, or real targets.
"""
import unittest


def authorized(grant, dispatch, accept_encoding=None):
    """Exact built-in identity/authorization agreement; ignore untrusted header."""
    del accept_encoding
    if type(grant) is not dict or type(dispatch) is not dict:
        return False
    if grant.get("active") is not True or grant.get("verified") is not True:
        return False
    if type(grant.get("revision")) is not int or grant["revision"] < 0:
        return False
    if type(dispatch.get("revision")) is not int:
        return False
    if grant["revision"] != dispatch["revision"]:
        return False
    for key in ("tenant", "request", "asset", "capability", "purpose"):
        left, right = grant.get(key), dispatch.get(key)
        if type(left) is not str or type(right) is not str:
            return False
        if not left or len(left) > 128 or left != right:
            return False
    return True


def fixture():
    identity = dict(tenant="tenant-lab", request="req-lab", asset="fixture-local",
                    capability="analysis-only", purpose="offline-reference", revision=0)
    return dict(identity, active=True, verified=True), dict(identity)


class AcceptEncodingNonAuthorityReferenceTests(unittest.TestCase):
    def test_matching_synthetic_context(self):
        grant, dispatch = fixture()
        self.assertTrue(authorized(grant, dispatch))

    def test_compression_preferences_do_not_mint_authority(self):
        for label in ("gzip", "br", "deflate", "identity", "*", "gzip, br", ""):
            with self.subTest(label=label):
                grant, dispatch = fixture()
                grant["active"] = False
                self.assertFalse(authorized(grant, dispatch, label))

    def test_hostile_header_objects_are_not_inspected(self):
        class Hostile:
            def __str__(self):
                raise AssertionError("header string conversion")
            def __bool__(self):
                raise AssertionError("header truthiness")
            def __iter__(self):
                raise AssertionError("header iteration")
        grant, dispatch = fixture()
        self.assertTrue(authorized(grant, dispatch, Hostile()))
        grant["verified"] = False
        self.assertFalse(authorized(grant, dispatch, Hostile()))

    def test_header_cannot_override_identity_mismatches(self):
        for field in ("tenant", "request", "asset", "capability", "purpose"):
            with self.subTest(field=field):
                grant, dispatch = fixture()
                dispatch[field] += "-foreign"
                self.assertFalse(authorized(grant, dispatch, "gzip"))

    def test_header_cannot_override_revision_mismatch(self):
        grant, dispatch = fixture()
        dispatch["revision"] = 1
        self.assertFalse(authorized(grant, dispatch, "identity"))

    def test_header_does_not_revoke_valid_synthetic_context(self):
        grant, dispatch = fixture()
        for label in (None, "unknown", "\\x00", object()):
            self.assertTrue(authorized(grant, dispatch, label))

    def test_bool_revision_is_rejected(self):
        grant, dispatch = fixture()
        dispatch["revision"] = False
        self.assertFalse(authorized(grant, dispatch, "br"))

    def test_string_subclass_identity_is_rejected(self):
        class Forged(str):
            pass
        grant, dispatch = fixture()
        dispatch["tenant"] = Forged(grant["tenant"])
        self.assertFalse(authorized(grant, dispatch, "gzip"))

    def test_missing_identity_fails_closed(self):
        grant, dispatch = fixture()
        del dispatch["asset"]
        self.assertFalse(authorized(grant, dispatch, "br"))

    def test_noncanonical_grant_or_dispatch_rejected(self):
        grant, dispatch = fixture()
        self.assertFalse(authorized(dict(grant), [], "br"))
        self.assertFalse(authorized([], dict(dispatch), "br"))

    def test_matching_malformed_identity_fails_closed(self):
        for value in ("", None, 1, True, [], {}, "x" * 129):
            with self.subTest(value=repr(value)):
                grant, dispatch = fixture()
                grant["asset"] = value
                dispatch["asset"] = value
                self.assertFalse(authorized(grant, dispatch, "gzip"))

    def test_grant_revision_type_confusion_fails_closed(self):
        for value in (True, 0.0, "0", None, -1):
            with self.subTest(value=repr(value)):
                grant, dispatch = fixture()
                grant["revision"] = value
                dispatch["revision"] = value
                self.assertFalse(authorized(grant, dispatch, "br"))

    def test_envelope_dictionary_subclasses_fail_closed(self):
        class ForgedDict(dict):
            pass
        grant, dispatch = fixture()
        self.assertFalse(authorized(ForgedDict(grant), dispatch, "gzip"))
        self.assertFalse(authorized(grant, ForgedDict(dispatch), "gzip"))

    def test_input_unchanged(self):
        grant, dispatch = fixture()
        original_grant, original_dispatch = dict(grant), dict(dispatch)
        authorized(grant, dispatch, {"malformed": ["object"]})
        self.assertEqual(grant, original_grant)
        self.assertEqual(dispatch, original_dispatch)


if __name__ == "__main__":
    unittest.main()
