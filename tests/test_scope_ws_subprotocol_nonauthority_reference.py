"""Offline contract: WebSocket subprotocol negotiation conveys no authorization.

Reference-only: does not represent production ToolExecutor enforcement.
Run: python -m unittest discover -s tests -p 'test_scope_ws_subprotocol_nonauthority_reference.py'
"""
import unittest
import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True)
class Grant:
    tenant: str
    asset: str
    capability: str
    revision: int
    approved: bool
    revoked: bool


def valid_identity(value):
    """Require canonical nonblank exact text with no control/format/separator chars."""
    return (type(value) is str and bool(value) and value == value.strip()
            and not any(unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Zl", "Zp")
                        for ch in value))


def reference_decide(grant, requested, headers):
    """Fail closed using trusted grant fields only; ignore caller presentation headers."""
    del headers
    if type(grant) is not Grant or type(requested) is not Grant:
        return False
    for item in (grant, requested):
        if any(not valid_identity(getattr(item, field))
               for field in ("tenant", "asset", "capability")):
            return False
        if type(item.revision) is not int or item.revision < 1:
            return False
        if type(item.approved) is not bool or type(item.revoked) is not bool:
            return False
    return (grant == requested and grant.approved is True and grant.revoked is False)


class WebSocketSubprotocolNonauthorityReference(unittest.TestCase):
    def setUp(self):
        self.valid = Grant("tenant-a", "lab-asset", "read-only", 3, True, False)

    def test_header_cannot_approve_unapproved_grant(self):
        unapproved = Grant("tenant-a", "lab-asset", "read-only", 3, False, False)
        for value in ("approved", "admin", "scope:all", "Bearer token", "", None,
                      ["approved"], {"approval": True}):
            with self.subTest(value=value):
                self.assertFalse(reference_decide(unapproved, unapproved,
                    {"Sec-WebSocket-Protocol": value}))

    def test_header_cannot_bypass_revocation(self):
        revoked = Grant("tenant-a", "lab-asset", "read-only", 3, True, True)
        for value in ("authorized", "revocation=false", "3", "read-only"):
            with self.subTest(value=value):
                self.assertFalse(reference_decide(revoked, revoked,
                    {"sec-websocket-protocol": value}))

    def test_header_cannot_widen_identity_or_capability(self):
        variants = [
            Grant("tenant-b", "lab-asset", "read-only", 3, True, False),
            Grant("tenant-a", "other-asset", "read-only", 3, True, False),
            Grant("tenant-a", "lab-asset", "active-scan", 3, True, False),
            Grant("tenant-a", "lab-asset", "read-only", 4, True, False),
        ]
        for variant in variants:
            with self.subTest(variant=variant):
                self.assertFalse(reference_decide(self.valid, variant,
                    {"Sec-WebSocket-Protocol": "tenant-a, lab-asset, active-scan, approved"}))

    def test_valid_grant_not_blocked_by_presentation_header(self):
        for headers in ({}, {"Sec-WebSocket-Protocol": "json"},
                        {"sec-websocket-protocol": "some-other-format"}):
            with self.subTest(headers=headers):
                self.assertTrue(reference_decide(self.valid, self.valid, headers))

    def test_malformed_stored_grant_cannot_gain_authority_from_header(self):
        variants = (
            Grant("", "lab-asset", "read-only", 3, True, False),
            Grant("tenant-a", "", "read-only", 3, True, False),
            Grant("tenant-a", "lab-asset", "", 3, True, False),
            Grant("tenant-a", "lab-asset", "read-only", 0, True, False),
            Grant("tenant-a", "lab-asset", "read-only", True, True, False),
            Grant("tenant-a", "lab-asset", "read-only", "3", True, False),
            Grant("tenant-a", "lab-asset", "read-only", 3, 1, False),
            Grant("tenant-a", "lab-asset", "read-only", 3, True, 0),
            Grant(42, "lab-asset", "read-only", 3, True, False),
        )
        for variant in variants:
            with self.subTest(variant=variant):
                self.assertFalse(reference_decide(variant, variant,
                    {"Sec-WebSocket-Protocol": "approved, admin, read-only"}))

    def test_grant_object_subclass_cannot_impersonate_exact_grant(self):
        class DerivedGrant(Grant):
            pass
        forged = DerivedGrant("tenant-a", "lab-asset", "read-only", 3, True, False)
        self.assertFalse(reference_decide(forged, forged,
            {"Sec-WebSocket-Protocol": "authorized"}))
        self.assertFalse(reference_decide(self.valid, forged,
            {"Sec-WebSocket-Protocol": "authorized"}))

    def test_replayed_old_revision_denied_even_with_matching_header(self):
        old = Grant("tenant-a", "lab-asset", "read-only", 2, True, False)
        self.assertFalse(reference_decide(self.valid, old,
            {"Sec-WebSocket-Protocol": "revision=3"}))
        self.assertFalse(reference_decide(old, self.valid,
            {"Sec-WebSocket-Protocol": "revision=2"}))

    def test_header_input_is_not_modified(self):
        headers = {"Sec-WebSocket-Protocol": ["json", "admin"], "Other": {"x": 1}}
        before = repr(headers)
        self.assertTrue(reference_decide(self.valid, self.valid, headers))
        self.assertEqual(repr(headers), before)

    def test_matching_poisoned_identity_is_still_denied(self):
        poisoned = (" tenant-a", "tenant-a ", "tenant-a\n", "tenant-a\x00",
                    "tenant-a\u200b", "tenant-a\u2028", "tenant-a\ud800")
        for value in poisoned:
            for field in ("tenant", "asset", "capability"):
                with self.subTest(value=ascii(value), field=field):
                    replacement = dict(tenant=self.valid.tenant, asset=self.valid.asset,
                                       capability=self.valid.capability)
                    replacement[field] = value
                    bad = Grant(**replacement, revision=3, approved=True, revoked=False)
                    self.assertFalse(reference_decide(bad, bad,
                        {"Sec-WebSocket-Protocol": "approved"}))

    def test_identity_subclasses_never_gain_grant_authority(self):
        class ForgedString(str):
            pass
        for field in ("tenant", "asset", "capability"):
            with self.subTest(field=field):
                replacement = dict(tenant=self.valid.tenant, asset=self.valid.asset,
                                   capability=self.valid.capability)
                replacement[field] = ForgedString(replacement[field])
                forged = Grant(**replacement, revision=3, approved=True, revoked=False)
                self.assertFalse(reference_decide(forged, forged,
                    {"Sec-WebSocket-Protocol": "authorized"}))

    def test_valid_distinct_unicode_identifier_remains_exact(self):
        other = Grant("tenant-é", "lab-asset", "read-only", 3, True, False)
        self.assertTrue(reference_decide(other, other, {}))
        decomposed = Grant("tenant-e\u0301", "lab-asset", "read-only", 3, True, False)
        self.assertFalse(reference_decide(other, decomposed,
            {"Sec-WebSocket-Protocol": "normalize=true"}))

    def test_control_fixtures_are_actual_codepoints(self):
        expected = (
            ("newline", "\n", "Cc"),
            ("nul", "\x00", "Cc"),
            ("zero_width", "\u200b", "Cf"),
            ("line_separator", "\u2028", "Zl"),
            ("surrogate", "\ud800", "Cs"),
        )
        for label, value, category in expected:
            with self.subTest(label=label):
                self.assertEqual(len(value), 1)
                self.assertEqual(unicodedata.category(value), category)
                self.assertFalse(valid_identity("tenant-a" + value))

    def test_header_cannot_repair_missing_grant_object(self):
        for grant, request in ((None, self.valid), (self.valid, None),
                               ({"approved": True}, self.valid),
                               (self.valid, {"approved": True})):
            with self.subTest(grant=type(grant).__name__, request=type(request).__name__):
                self.assertFalse(reference_decide(grant, request,
                    {"Sec-WebSocket-Protocol": "admin, approved, read-only"}))

    def test_rejected_request_revision_cannot_be_hidden_by_header(self):
        for revision in (None, False, 0, -1, 3.0, "3", [], {}):
            request = Grant("tenant-a", "lab-asset", "read-only", revision, True, False)
            with self.subTest(revision=revision):
                self.assertFalse(reference_decide(self.valid, request,
                    {"Sec-WebSocket-Protocol": "revision=3, approved"}))

    def test_grant_decisions_ignore_presentation_value_shapes(self):
        for headers in (None, False, 42, "", [], {"Sec-WebSocket-Protocol": object()},
                        {"Sec-WebSocket-Protocol": ["admin", {"approved": True}]}):
            with self.subTest(header_type=type(headers).__name__):
                self.assertTrue(reference_decide(self.valid, self.valid, headers))

    def test_denial_matrix_has_no_mock_handler_side_effects(self):
        denied = (
            (Grant("tenant-a", "lab-asset", "read-only", 3, False, False),
             Grant("tenant-a", "lab-asset", "read-only", 3, False, False)),
            (Grant("tenant-a", "lab-asset", "read-only", 3, True, True),
             Grant("tenant-a", "lab-asset", "read-only", 3, True, True)),
            (self.valid, Grant("tenant-b", "lab-asset", "read-only", 3, True, False)),
            (self.valid, Grant("tenant-a", "other-asset", "read-only", 3, True, False)),
            (self.valid, Grant("tenant-a", "lab-asset", "active-scan", 3, True, False)),
            (self.valid, Grant("tenant-a", "lab-asset", "read-only", 2, True, False)),
            (None, self.valid),
            (self.valid, None),
        )
        calls = []
        for stored, request in denied:
            if reference_decide(stored, request,
                                {"Sec-WebSocket-Protocol": "admin, approved"}):
                calls.append((stored, request))
        self.assertEqual(calls, [])

    def test_valid_control_can_reach_mock_handler_once(self):
        calls = []
        if reference_decide(self.valid, self.valid, {"Sec-WebSocket-Protocol": "json"}):
            calls.append("executed")
        self.assertEqual(calls, ["executed"])

    def test_all_ascii_controls_and_del_denied_even_on_exact_match(self):
        for codepoint in tuple(range(32)) + (127,):
            poisoned = "tenant-a" + chr(codepoint)
            for field in ("tenant", "asset", "capability"):
                with self.subTest(codepoint=codepoint, field=field):
                    values = dict(tenant=self.valid.tenant, asset=self.valid.asset,
                                  capability=self.valid.capability)
                    values[field] = poisoned
                    grant = Grant(**values, revision=3, approved=True, revoked=False)
                    self.assertFalse(reference_decide(grant, grant,
                        {"Sec-WebSocket-Protocol": "approved"}))

    def test_header_authority_tokens_cannot_reverse_explicit_denial(self):
        denied = Grant("tenant-a", "lab-asset", "read-only", 3, False, False)
        payloads = (
            "admin", "approved", "allow=true", "scope:all", "revision=3",
            "tenant=tenant-a", "asset=lab-asset", "capability=read-only",
            "revoked=false", "operator-approved",
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                self.assertFalse(reference_decide(denied, denied,
                    {"Sec-WebSocket-Protocol": payload}))

    def test_rejected_identity_mutations_do_not_trigger_mock_handler(self):
        attempts = []
        for field in ("tenant", "asset", "capability"):
            for replacement in ("", " forged", "forged ", "forged\\x00", "forged\\u200b"):
                values = dict(tenant=self.valid.tenant, asset=self.valid.asset,
                              capability=self.valid.capability)
                values[field] = replacement
                request = Grant(**values, revision=3, approved=True, revoked=False)
                if reference_decide(self.valid, request,
                                    {"Sec-WebSocket-Protocol": "approved"}):
                    attempts.append((field, replacement))
        self.assertEqual(attempts, [])

    def test_reversed_approval_or_revocation_flags_never_authorize(self):
        for approved, revoked in ((False, False), (False, True), (True, True)):
            grant = Grant("tenant-a", "lab-asset", "read-only", 3, approved, revoked)
            with self.subTest(approved=approved, revoked=revoked):
                self.assertFalse(reference_decide(grant, grant,
                    {"Sec-WebSocket-Protocol": "admin"}))

    def test_header_cannot_override_revocation_across_identity_roles(self):
        for role in ("tenant", "asset", "capability"):
            with self.subTest(role=role):
                values = dict(tenant=self.valid.tenant, asset=self.valid.asset,
                              capability=self.valid.capability)
                values[role] = "other-value"
                revoked = Grant(**values, revision=3, approved=True, revoked=True)
                self.assertFalse(reference_decide(revoked, revoked,
                    {"Sec-WebSocket-Protocol": "revoked=false, approved, admin"}))

    def test_malformed_approval_metadata_has_no_handler_side_effect(self):
        calls = []
        for approved in (None, 0, 1, "true", [], {}):
            grant = Grant("tenant-a", "lab-asset", "read-only", 3, approved, False)
            if reference_decide(grant, grant, {"Sec-WebSocket-Protocol": "approved"}):
                calls.append(approved)
        self.assertEqual(calls, [])

    def test_request_approval_is_not_independent_authority(self):
        stored = Grant("tenant-a", "lab-asset", "read-only", 3, False, False)
        request = Grant("tenant-a", "lab-asset", "read-only", 3, True, False)
        self.assertFalse(reference_decide(stored, request,
            {"Sec-WebSocket-Protocol": "admin, approved"}))

    def test_revoked_stored_grant_cannot_be_replaced_by_clean_request(self):
        stored = Grant("tenant-a", "lab-asset", "read-only", 3, True, True)
        request = Grant("tenant-a", "lab-asset", "read-only", 3, True, False)
        self.assertFalse(reference_decide(stored, request,
            {"Sec-WebSocket-Protocol": "revoked=false"}))

    def test_full_c0_del_denial_propagates_to_mock_dispatch(self):
        calls = []
        for codepoint in tuple(range(32)) + (127,):
            for role in ("tenant", "asset", "capability"):
                values = dict(tenant=self.valid.tenant, asset=self.valid.asset,
                              capability=self.valid.capability)
                values[role] = "identity" + chr(codepoint)
                poisoned = Grant(**values, revision=3, approved=True, revoked=False)
                if reference_decide(poisoned, poisoned,
                                    {"Sec-WebSocket-Protocol": "approved"}):
                    calls.append((role, codepoint))
        self.assertEqual(calls, [])

    def test_all_denials_ignore_requested_header_container_identity(self):
        revoked = Grant("tenant-a", "lab-asset", "read-only", 3, True, True)
        for headers in (None, (), [], {"Sec-WebSocket-Protocol": "approved"},
                        {"Sec-WebSocket-Protocol": ["admin"]}, object()):
            with self.subTest(header_type=type(headers).__name__):
                self.assertFalse(reference_decide(revoked, revoked, headers))

    def test_revocation_transition_disables_later_mock_dispatch(self):
        calls = []
        initially_allowed = self.valid
        later_revoked = Grant("tenant-a", "lab-asset", "read-only", 3, True, True)
        for stored in (initially_allowed, later_revoked, later_revoked):
            if reference_decide(stored, self.valid,
                                {"Sec-WebSocket-Protocol": "approved"}):
                calls.append("handler")
        self.assertEqual(calls, ["handler"])

    def test_grant_revision_change_requires_new_matching_request(self):
        next_revision = Grant("tenant-a", "lab-asset", "read-only", 4, True, False)
        self.assertFalse(reference_decide(next_revision, self.valid,
            {"Sec-WebSocket-Protocol": "revision=4"}))
        self.assertTrue(reference_decide(next_revision, next_revision, {}))

    def test_request_replay_after_revocation_has_no_handler_calls(self):
        revoked = Grant("tenant-a", "lab-asset", "read-only", 3, True, True)
        calls = []
        for _ in range(20):
            if reference_decide(revoked, self.valid,
                                {"Sec-WebSocket-Protocol": "approved, revocation=false"}):
                calls.append("called")
        self.assertEqual(calls, [])

    def test_future_revision_header_does_not_upgrade_stored_grant(self):
        for claimed in ("revision=4", "revision=999", "approved;rev=4"):
            with self.subTest(claimed=claimed):
                request = Grant("tenant-a", "lab-asset", "read-only", 4, True, False)
                self.assertFalse(reference_decide(self.valid, request,
                    {"Sec-WebSocket-Protocol": claimed}))

    def test_revoked_grant_remains_denied_across_header_replay_matrix(self):
        revoked = Grant("tenant-a", "lab-asset", "read-only", 3, True, True)
        calls = []
        header_values = ("approved", "admin", "revoked=false", "revision=3",
                         "tenant=tenant-a", "scope:all", "read-only")
        for token in header_values:
            for _ in range(5):
                if reference_decide(revoked, self.valid,
                                    {"Sec-WebSocket-Protocol": token}):
                    calls.append(token)
        self.assertEqual(calls, [])

    def test_malformed_stored_revision_never_recovers_using_valid_request(self):
        for bad_revision in (None, False, 0, -1, 3.0, "3", [], {}):
            stored = Grant("tenant-a", "lab-asset", "read-only",
                           bad_revision, True, False)
            with self.subTest(revision=bad_revision):
                self.assertFalse(reference_decide(stored, self.valid,
                    {"Sec-WebSocket-Protocol": "revision=3"}))

    def test_denied_grant_remains_denied_under_all_header_case_variants(self):
        denied = Grant("tenant-a", "lab-asset", "read-only", 3, False, False)
        for key in ("Sec-WebSocket-Protocol", "sec-websocket-protocol",
                    "SEC-WEBSOCKET-PROTOCOL", "sEc-WeBsOcKeT-pRoToCoL"):
            with self.subTest(key=key):
                self.assertFalse(reference_decide(denied, denied,
                    {key: "admin, approved, revoked=false"}))

    def test_unsupported_grant_object_is_denied_without_header_access(self):
        class ExplodingHeaders:
            def __iter__(self):
                raise AssertionError("header should not be inspected")
        self.assertFalse(reference_decide(None, self.valid, ExplodingHeaders()))

    def test_stored_approval_does_not_inherit_request_authority(self):
        calls = []
        for approved, revoked in ((False, False), (False, True), (True, True)):
            stored = Grant("tenant-a", "lab-asset", "read-only", 3, approved, revoked)
            request = self.valid
            if reference_decide(stored, request,
                                {"Sec-WebSocket-Protocol": "approved, revocation=false"}):
                calls.append((approved, revoked))
        self.assertEqual(calls, [])

    def test_consistent_valid_grant_header_fuzz_is_presentation_only(self):
        for value in (None, object(), False, 123, ["scope:all"],
                      {"admin": True}, "revoked=true", "tenant=other"):
            with self.subTest(value_type=type(value).__name__):
                self.assertTrue(reference_decide(self.valid, self.valid,
                    {"Sec-WebSocket-Protocol": value}))

    def test_consent_denial_is_monotone_under_extra_header_claims(self):
        denied = Grant("tenant-a", "lab-asset", "read-only", 3, False, False)
        headers = {}
        claims = ("approved", "admin", "revoked=false", "revision=3", "scope:all")
        for claim in claims:
            headers["Sec-WebSocket-Protocol"] = ", ".join(claims[:claims.index(claim) + 1])
            with self.subTest(claim=claim):
                self.assertFalse(reference_decide(denied, denied, headers))

    def test_valid_stored_grant_cannot_approve_invalid_requested_state(self):
        requests = (
            Grant("tenant-a", "lab-asset", "read-only", 3, False, False),
            Grant("tenant-a", "lab-asset", "read-only", 3, True, True),
            Grant("tenant-a", "lab-asset", "read-only", 0, True, False),
        )
        for requested in requests:
            with self.subTest(requested=requested):
                self.assertFalse(reference_decide(self.valid, requested,
                    {"Sec-WebSocket-Protocol": "approved"}))

    def test_reference_rejects_untrusted_grant_subclass_with_overridden_equality(self):
        class ForgedGrant(Grant):
            def __eq__(self, other):
                return True
        forged = ForgedGrant("tenant-a", "lab-asset", "read-only", 3, True, False)
        self.assertFalse(reference_decide(forged, self.valid,
            {"Sec-WebSocket-Protocol": "approved"}))
        self.assertFalse(reference_decide(self.valid, forged,
            {"Sec-WebSocket-Protocol": "approved"}))

    def test_reference_rejects_request_identity_subclass_even_if_text_matches(self):
        class ForgedIdentity(str):
            def __eq__(self, other):
                return True
        req = Grant(ForgedIdentity("tenant-a"), "lab-asset", "read-only", 3, True, False)
        self.assertFalse(reference_decide(self.valid, req, {}))

    def test_denial_never_invokes_side_effect_boundary(self):
        """Instrument the offline call boundary, not production ToolExecutor."""
        effects = []
        def dispatch(stored, request, headers):
            if not reference_decide(stored, request, headers):
                return False
            effects.extend(("handler", "evidence_write", "network_open"))
            return True

        denied = (
            Grant("tenant-a", "lab-asset", "read-only", 3, False, False),
            Grant("tenant-a", "lab-asset", "read-only", 3, True, True),
            Grant("tenant-b", "lab-asset", "read-only", 3, True, False),
            Grant("tenant-a", "lab-asset", "read-only", 4, True, False),
        )
        for invalid in denied:
            with self.subTest(invalid=invalid):
                self.assertFalse(dispatch(invalid, self.valid,
                    {"Sec-WebSocket-Protocol": "admin, approved"}))
        self.assertEqual(effects, [])
        self.assertTrue(dispatch(self.valid, self.valid, {}))
        self.assertEqual(effects, ["handler", "evidence_write", "network_open"])

    def test_revoked_grant_cannot_execute_even_when_requested_matches_otherwise(self):
        side_effects = []
        revoked = Grant("tenant-a", "lab-asset", "read-only", 3, True, True)
        for candidate in (revoked, self.valid):
            if reference_decide(revoked, candidate, {}):
                side_effects.append("executor")
        self.assertEqual(side_effects, [])

    def test_reference_denies_distinct_normalization_forms_without_coercion(self):
        composed = Grant("ténant", "lab-asset", "read-only", 3, True, False)
        decomposed = Grant("te\u0301nant", "lab-asset", "read-only", 3, True, False)
        self.assertFalse(reference_decide(composed, decomposed,
            {"Sec-WebSocket-Protocol": "approved"}))
        self.assertTrue(reference_decide(composed, composed, {}))

    def test_grant_and_request_type_mismatch_remains_fail_closed(self):
        for malformed in (None, {}, [], "approved", 42, object()):
            with self.subTest(type=type(malformed).__name__):
                self.assertFalse(reference_decide(malformed, self.valid, {}))
                self.assertFalse(reference_decide(self.valid, malformed, {}))

    def test_denial_does_not_evaluate_header_properties(self):
        class ExplodingMapping(dict):
            def __getitem__(self, key):
                raise AssertionError("headers are presentation-only")
            def get(self, key, default=None):
                raise AssertionError("headers are presentation-only")
        revoked = Grant("tenant-a", "lab-asset", "read-only", 3, True, True)
        self.assertFalse(reference_decide(revoked, revoked, ExplodingMapping()))
        self.assertTrue(reference_decide(self.valid, self.valid, ExplodingMapping()))

    def test_denied_stored_grant_cannot_be_reenabled_by_mutating_headers(self):
        denied = Grant("tenant-a", "lab-asset", "read-only", 3, False, False)
        headers = {"Sec-WebSocket-Protocol": "approved"}
        effects = []
        for claimed in ("admin", "approved", "revoked=false", "scope:all"):
            headers["Sec-WebSocket-Protocol"] = claimed
            if reference_decide(denied, self.valid, headers):
                effects.append(claimed)
        self.assertEqual(effects, [])

    def test_valid_grant_is_independent_of_header_mutation(self):
        headers = {"Sec-WebSocket-Protocol": "approved"}
        outcomes = []
        for claimed in ("admin", "", None, ["read-only"], {"approved": False}):
            headers["Sec-WebSocket-Protocol"] = claimed
            outcomes.append(reference_decide(self.valid, self.valid, headers))
        self.assertEqual(outcomes, [True] * 5)

    def test_denial_never_calls_handler(self):
        revoked = Grant("tenant-a", "lab-asset", "read-only", 3, True, True)
        calls = []
        def mock_handler():
            calls.append(True)
        for header in ("admin", "approved", "read-only", ""):
            if reference_decide(revoked, revoked, {"Sec-WebSocket-Protocol": header}):
                mock_handler()
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
