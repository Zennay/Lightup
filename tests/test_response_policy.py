"""Cookie and CORS checks of the lab HTTP baseline worker."""

import unittest

from lightup.workers.http_baseline import PROBE_ORIGIN, evaluate_response


def ids(headers):
    return {i.check_id for i in evaluate_response(tuple(headers))}


class ResponsePolicyTest(unittest.TestCase):
    def test_cookie_attributes_are_checked_per_cookie(self):
        self.assertIn("cookie-missing-httponly", ids([("Set-Cookie", "a=1; Path=/")]))
        # One compliant cookie must not mask a second, weak one.
        weak_second = [("Set-Cookie", "a=1; HttpOnly; SameSite=Lax"),
                       ("Set-Cookie", "b=2; Path=/")]
        self.assertTrue({"cookie-missing-httponly", "cookie-missing-samesite"}
                        <= ids(weak_second))
        good = [("set-cookie", "a=1; httponly; samesite=Strict")]
        self.assertFalse({"cookie-missing-httponly", "cookie-missing-samesite"} & ids(good))

    def test_no_cookie_means_no_cookie_findings(self):
        self.assertFalse({i for i in ids([]) if i.startswith("cookie-")})

    def test_cors_wildcard_and_reflection(self):
        self.assertIn("cors-wildcard-origin",
                      ids([("Access-Control-Allow-Origin", "*")]))
        reflect = [("Access-Control-Allow-Origin", PROBE_ORIGIN),
                   ("Access-Control-Allow-Credentials", "true")]
        self.assertIn("cors-reflected-origin-with-credentials", ids(reflect))

    def test_reflection_without_credentials_or_fixed_origin_is_not_flagged(self):
        self.assertFalse({i for i in ids([("Access-Control-Allow-Origin", PROBE_ORIGIN)])
                          if i.startswith("cors-")})
        fixed = [("Access-Control-Allow-Origin", "https://app.example"),
                 ("Access-Control-Allow-Credentials", "true")]
        self.assertFalse({i for i in ids(fixed) if i.startswith("cors-")})


if __name__ == "__main__":
    unittest.main()
