"""Offline reference: WebSocket subprotocol labels cannot authorize active dispatch.

Synthetic fixtures only. This is not production enforcement or issuer verification.
"""
import unittest


def permitted(grant, dispatch, subprotocol):
    # Transport metadata must never be consulted, parsed or coerced.
    del subprotocol
    if type(grant) is not dict or type(dispatch) is not dict:
        return False
    if grant.get("active") is not True or grant.get("issuer_verified") is not True:
        return False
    for key in ("tenant", "request", "asset", "capability"):
        left, right = grant.get(key), dispatch.get(key)
        if type(left) is not str or type(right) is not str or not left or left != right:
            return False
    left, right = grant.get("revision"), dispatch.get("revision")
    return type(left) is int and type(right) is int and left >= 0 and left == right


class HostileLabel:
    def __str__(self):
        raise AssertionError("subprotocol str invoked")

    def __bool__(self):
        raise AssertionError("subprotocol bool invoked")

    def __iter__(self):
        raise AssertionError("subprotocol iteration invoked")


class TestSubprotocolNonAuthority(unittest.TestCase):
    def setUp(self):
        self.grant = dict(tenant="tenant-a", request="request-a", asset="asset-a",
                          capability="header-baseline", revision=0,
                          active=True, issuer_verified=True)
        self.dispatch = {k: self.grant[k] for k in
                         ("tenant", "request", "asset", "capability", "revision")}

    def test_valid_grant_independent_of_label(self):
        for label in (None, "", "admin", "scope=all", HostileLabel(), ["admin"], {"role": "admin"}):
            with self.subTest(label=type(label).__name__):
                self.assertTrue(permitted(self.grant, self.dispatch, label))

    def test_inactive_or_unverified_never_revived(self):
        for key in ("active", "issuer_verified"):
            with self.subTest(key=key):
                grant = dict(self.grant, **{key: False})
                self.assertFalse(permitted(grant, self.dispatch, "admin,scope=all"))

    def test_identity_swaps_refused(self):
        for key in ("tenant", "request", "asset", "capability"):
            with self.subTest(key=key):
                dispatch = dict(self.dispatch, **{key: "other"})
                self.assertFalse(permitted(self.grant, dispatch, "admin"))

    def test_revision_mismatch_refused(self):
        self.assertFalse(permitted(self.grant, dict(self.dispatch, revision=1), "admin"))

    def test_bool_revision_refused(self):
        self.assertFalse(permitted(self.grant, dict(self.dispatch, revision=False), "admin"))

    def test_nonstring_matching_identity_refused(self):
        for key in ("tenant", "request", "asset", "capability"):
            with self.subTest(key=key):
                grant, dispatch = dict(self.grant), dict(self.dispatch)
                grant[key] = dispatch[key] = 42
                self.assertFalse(permitted(grant, dispatch, "admin"))

    def test_polymorphic_envelope_refused(self):
        class DictSubclass(dict):
            pass
        self.assertFalse(permitted(DictSubclass(self.grant), self.dispatch, "admin"))
        self.assertFalse(permitted(self.grant, DictSubclass(self.dispatch), "admin"))


    def test_missing_identity_or_revision_refused(self):
        for key in ("tenant", "request", "asset", "capability", "revision"):
            with self.subTest(key=key):
                grant, dispatch = dict(self.grant), dict(self.dispatch)
                grant.pop(key)
                self.assertFalse(permitted(grant, dispatch, "admin"))
                grant = dict(self.grant)
                dispatch.pop(key)
                self.assertFalse(permitted(grant, dispatch, "admin"))

    def test_matching_empty_identity_refused(self):
        for key in ("tenant", "request", "asset", "capability"):
            with self.subTest(key=key):
                grant, dispatch = dict(self.grant), dict(self.dispatch)
                grant[key] = dispatch[key] = ""
                self.assertFalse(permitted(grant, dispatch, "admin"))

    def test_matching_string_subclass_refused(self):
        class ForgedStr(str):
            pass
        for key in ("tenant", "request", "asset", "capability"):
            with self.subTest(key=key):
                grant, dispatch = dict(self.grant), dict(self.dispatch)
                grant[key] = dispatch[key] = ForgedStr(grant[key])
                self.assertFalse(permitted(grant, dispatch, "admin"))

    def test_grant_revision_type_confusion_refused(self):
        for invalid in (True, False, 0.0, "0", None, -1):
            with self.subTest(invalid=repr(invalid)):
                grant = dict(self.grant, revision=invalid)
                self.assertFalse(permitted(grant, self.dispatch, "admin"))

    def test_hostile_label_accessors_never_called(self):
        class Hostile:
            def __getattribute__(self, name):
                raise AssertionError("label attribute accessed")
            def __len__(self):
                raise AssertionError("label length accessed")
            def __eq__(self, other):
                raise AssertionError("label compared")
        self.assertTrue(permitted(self.grant, self.dispatch, Hostile()))
        self.assertFalse(permitted(dict(self.grant, active=False), self.dispatch, Hostile()))


    def test_truthy_but_not_boolean_grant_flags_refused(self):
        for key in ("active", "issuer_verified"):
            for invalid in (1, "true", ["yes"], object()):
                with self.subTest(key=key, invalid=type(invalid).__name__):
                    grant = dict(self.grant, **{key: invalid})
                    self.assertFalse(permitted(grant, self.dispatch, "admin"))

    def test_identity_missing_on_both_sides_refused(self):
        for key in ("tenant", "request", "asset", "capability"):
            with self.subTest(key=key):
                grant, dispatch = dict(self.grant), dict(self.dispatch)
                grant.pop(key)
                dispatch.pop(key)
                self.assertFalse(permitted(grant, dispatch, "admin"))

    def test_inputs_unchanged_by_metadata_independence(self):
        grant, dispatch = dict(self.grant), dict(self.dispatch)
        before_grant, before_dispatch = dict(grant), dict(dispatch)
        self.assertTrue(permitted(grant, dispatch, HostileLabel()))
        self.assertEqual(grant, before_grant)
        self.assertEqual(dispatch, before_dispatch)


if __name__ == "__main__":
    unittest.main()
