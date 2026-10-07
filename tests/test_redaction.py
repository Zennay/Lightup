import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.redaction import redact_text


class RedactionTests(unittest.TestCase):
    def test_bearer_token_is_redacted(self):
        value = "Authorization: Bearer abc.def.ghi"
        output = redact_text(value)
        self.assertNotIn("abc.def.ghi", output)
        self.assertIn("[REDACTED]", output)

    def test_basic_authorization_credential_is_redacted(self):
        value = "Authorization: Basic dXNlcjpwYXNzd29yZA=="
        output = redact_text(value)
        self.assertEqual(output, "Authorization: Basic [REDACTED]")

    def test_basic_authorization_redaction_is_case_insensitive(self):
        value = "authorization: basic Zm9vOmJhcg=="
        output = redact_text(value)
        self.assertNotIn("Zm9vOmJhcg==", output)
        self.assertTrue(output.endswith("[REDACTED]"))

    def test_proxy_basic_authorization_credential_is_redacted(self):
        value = "Proxy-Authorization: Basic YWxpY2U6c2VjcmV0"
        output = redact_text(value)
        self.assertEqual(output, "Proxy-Authorization: Basic [REDACTED]")

    def test_arbitrary_authorization_scheme_payload_is_redacted(self):
        value = (
            'Authorization: Digest username="alice", realm="admin", '
            'response="0123456789abcdef"'
        )
        self.assertEqual(redact_text(value), "Authorization: Digest [REDACTED]")

    def test_proxy_authorization_scheme_payload_is_redacted(self):
        value = "proxy-authorization: Negotiate TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA="
        self.assertEqual(
            redact_text(value),
            "proxy-authorization: Negotiate [REDACTED]",
        )

    def test_authorization_word_in_unrelated_text_is_unchanged(self):
        value = "authorization status: denied"
        self.assertEqual(redact_text(value), value)

    def test_url_userinfo_credentials_are_redacted_without_losing_target_context(self):
        value = "https://alice:secret@example.test:8443/path?q=1#frag"
        output = redact_text(value)
        self.assertEqual(
            output,
            "https://[REDACTED]@example.test:8443/path?q=1#frag",
        )
        self.assertNotIn("alice:secret", output)

    def test_url_username_only_userinfo_is_redacted(self):
        value = "http://opaque-token@example.test/resource"
        output = redact_text(value)
        self.assertEqual(output, "http://[REDACTED]@example.test/resource")

    def test_url_without_userinfo_is_unchanged_even_when_query_contains_at_sign(self):
        value = "https://example.test/path?contact=ops@example.test#status"
        self.assertEqual(redact_text(value), value)

    def test_cookie_header_value_is_redacted(self):
        value = "Cookie: session=abc123; csrf=def456"
        self.assertEqual(redact_text(value), "Cookie: [REDACTED]")

    def test_set_cookie_header_value_and_attributes_are_redacted(self):
        value = "Set-Cookie: session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict"
        self.assertEqual(redact_text(value), "Set-Cookie: [REDACTED]")

    def test_cookie_redaction_is_case_insensitive_and_line_bounded(self):
        value = (
            "X-Trace: keep\n"
            "cookie: session=abc123\n"
            "Content-Type: text/plain"
        )
        self.assertEqual(
            redact_text(value),
            "X-Trace: keep\ncookie: [REDACTED]\nContent-Type: text/plain",
        )

    def test_compound_token_assignments_are_redacted_without_consuming_query_tail(self):
        cases = (
            ("access_token=abc123&scope=read", "access_token=[REDACTED]&scope=read"),
            ("refresh-token=def456&next=1", "refresh-token=[REDACTED]&next=1"),
            ("id_token: ghi789", "id_token=[REDACTED]"),
            ("auth-token='jkl012'", "auth-token=[REDACTED]"),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(redact_text(value), expected)

    def test_client_secret_assignment_is_redacted(self):
        self.assertEqual(
            redact_text('client_secret="supersecret"'),
            "client_secret=[REDACTED]",
        )

    def test_unrelated_compound_key_is_unchanged(self):
        value = "session_tokenizer=ordinary-value"
        self.assertEqual(redact_text(value), value)

    def test_common_secret_assignment_preserves_query_tail(self):
        self.assertEqual(
            redact_text("api_key=supersecret&next=1"),
            "api_key=[REDACTED]&next=1",
        )

    def test_common_secret_assignment_is_redacted(self):
        output = redact_text("api_key=supersecret")
        self.assertNotIn("supersecret", output)


if __name__ == "__main__":
    unittest.main()
