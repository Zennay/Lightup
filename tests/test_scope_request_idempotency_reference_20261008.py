"""Offline reference for fail-closed authorization-request idempotency.

No production imports, network access, target contact or executable authorization.
"""
import unittest


def submit_request(records, *, tenant, engagement, nonce, digest):
    """Pure reference: same nonce is retry-safe only for the identical request."""
    if not all(type(v) is str and v and v.isascii() for v in (tenant, engagement, nonce, digest)):
        return "DENY_INVALID"
    if len(nonce) > 128 or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        return "DENY_INVALID"
    key = (tenant, engagement, nonce)
    previous = records.get(key)
    if previous is None:
        records[key] = digest
        return "CREATED_PENDING_REVIEW"
    if type(previous) is not str:
        return "DENY_CORRUPT_STATE"
    if previous != digest:
        return "DENY_NONCE_REUSE_CHANGED_REQUEST"
    return "RETRY_PENDING_REVIEW"


class IdempotencyReferenceTests(unittest.TestCase):
    A = "a" * 64
    B = "b" * 64

    def test_first_submit_is_only_pending_not_approved(self):
        self.assertEqual(submit_request({}, tenant="t", engagement="e", nonce="n", digest=self.A),
                         "CREATED_PENDING_REVIEW")

    def test_identical_retry_does_not_create_second_request(self):
        state = {}
        self.assertEqual(submit_request(state, tenant="t", engagement="e", nonce="n", digest=self.A),
                         "CREATED_PENDING_REVIEW")
        self.assertEqual(submit_request(state, tenant="t", engagement="e", nonce="n", digest=self.A),
                         "RETRY_PENDING_REVIEW")
        self.assertEqual(len(state), 1)

    def test_changed_payload_with_reused_nonce_denied(self):
        state = {}
        submit_request(state, tenant="t", engagement="e", nonce="n", digest=self.A)
        self.assertEqual(submit_request(state, tenant="t", engagement="e", nonce="n", digest=self.B),
                         "DENY_NONCE_REUSE_CHANGED_REQUEST")
        self.assertEqual(state[("t", "e", "n")], self.A)

    def test_key_is_bound_to_tenant_and_engagement(self):
        state = {}
        for tenant, engagement in [("t1", "e1"), ("t2", "e1"), ("t1", "e2")]:
            self.assertEqual(submit_request(state, tenant=tenant, engagement=engagement,
                                            nonce="n", digest=self.A), "CREATED_PENDING_REVIEW")
        self.assertEqual(len(state), 3)

    def test_invalid_identity_or_nonce_rejected_without_write(self):
        for value in ("", "é", "\n", 0, False, None, "x" * 129):
            state = {}
            self.assertEqual(submit_request(state, tenant="t", engagement="e", nonce=value,
                                            digest=self.A), "DENY_INVALID")
            self.assertEqual(state, {})

    def test_digest_must_be_canonical_lowercase_hex(self):
        for digest in ("a" * 63, "A" * 64, "z" * 64, "", 123, True):
            self.assertEqual(submit_request({}, tenant="t", engagement="e", nonce="n",
                                            digest=digest), "DENY_INVALID")

    def test_corrupt_prior_record_denied(self):
        state = {("t", "e", "n"): None}
        self.assertEqual(submit_request(state, tenant="t", engagement="e", nonce="n",
                                        digest=self.A), "DENY_CORRUPT_STATE")

    def test_no_retry_can_return_approved_or_executable(self):
        state = {}
        outcomes = [submit_request(state, tenant="t", engagement="e", nonce="n", digest=d)
                    for d in (self.A, self.A, self.B)]
        self.assertTrue(all("APPROVED" not in item and "EXECUTE" not in item for item in outcomes))


if __name__ == "__main__":
    unittest.main()
