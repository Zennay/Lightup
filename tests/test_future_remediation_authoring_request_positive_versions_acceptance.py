from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import unittest

import test_future_remediation_authoring_request as request_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_authoring_request_handoff import (
    future_remediation_authoring_request_from_dict,
)


def _recompute_request_sha256(payload: dict) -> str:
    digest_payload = deepcopy(payload)
    digest_payload.pop("request_sha256")
    return sha256(
        json.dumps(
            digest_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


class FutureRemediationAuthoringRequestPositiveVersionAcceptanceTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = request_tests.FutureRemediationAuthoringRequestTest(
            "test_request_is_deterministic_and_export_is_bounded"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _canonical_payload(self) -> dict:
        produced = self.base._request(
            AttackPathTransitionClassification.WORSENED,
            suffix="authoring-positive-version-acceptance",
        )
        payload = json.loads(produced[-1].to_json())
        self.assertGreater(payload["current_twin_version"], 0)
        self.assertGreater(payload["twin_version"], 0)
        self.assertEqual(
            future_remediation_authoring_request_from_dict(payload),
            produced[-1],
        )
        return payload

    def test_zero_twin_versions_fail_closed_even_with_matching_digest(self):
        payload = self._canonical_payload()

        for field in ("current_twin_version", "twin_version"):
            with self.subTest(field=field):
                forged = deepcopy(payload)
                forged[field] = 0
                forged["request_sha256"] = _recompute_request_sha256(forged)

                with self.assertRaisesRegex(
                    ValueError,
                    rf"remediation authoring request {field} must be a positive integer",
                ):
                    future_remediation_authoring_request_from_dict(forged)


if __name__ == "__main__":
    unittest.main()
