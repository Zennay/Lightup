from __future__ import annotations

import copy
from hashlib import sha256
import json
import unittest

import test_future_security_retest_request as request_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_retest_request_handoff import (
    future_security_retest_request_from_dict,
)


def _resign(payload: dict) -> None:
    digest_payload = copy.deepcopy(payload)
    digest_payload.pop("request_sha256")
    payload["request_sha256"] = sha256(
        json.dumps(
            digest_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


class FutureSecurityRetestRequestPositiveVersionAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.r = request_tests.FutureSecurityRetestRequestTest(
            "test_request_is_deterministic_lineage_bound_and_read_only"
        )
        self.r.setUp()
        self.addCleanup(self.r.tearDown)

    def _payload(self) -> dict:
        *_, request = self.r._request(
            AttackPathTransitionClassification.WORSENED,
            suffix="retest-handoff-positive-version",
        )
        return json.loads(request.to_json())

    def test_canonical_producer_payload_round_trips(self):
        payload = self._payload()
        parsed = future_security_retest_request_from_dict(copy.deepcopy(payload))
        self.assertEqual(json.loads(parsed.to_json()), payload)

    def test_zero_twin_versions_fail_closed_with_matching_digest(self):
        payload = self._payload()

        for field in ("current_twin_version", "twin_version"):
            with self.subTest(field=field):
                tampered = copy.deepcopy(payload)
                tampered[field] = 0
                _resign(tampered)

                with self.assertRaises(ValueError):
                    future_security_retest_request_from_dict(tampered)


if __name__ == "__main__":
    unittest.main()
