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


def _rehash_request(payload: dict) -> None:
    digest_payload = deepcopy(payload)
    digest_payload.pop("request_sha256")
    payload["request_sha256"] = sha256(
        json.dumps(
            digest_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


class FutureRemediationAuthoringRequestTopLevelLineageAcceptanceTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = request_tests.FutureRemediationAuthoringRequestTest(
            "test_request_is_deterministic_and_export_is_bounded"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _payload(self, *, suffix: str) -> tuple[object, dict]:
        produced = self.base._request(
            AttackPathTransitionClassification.WORSENED,
            suffix=suffix,
        )
        request = produced[-1]
        payload = json.loads(request.to_json())
        return request, payload

    def test_canonical_producer_request_round_trips(self):
        request, payload = self._payload(
            suffix="authoring-top-level-lineage-control"
        )
        self.assertEqual(
            future_remediation_authoring_request_from_dict(payload),
            request,
        )

    def test_top_level_lineage_rejects_noncanonical_text_with_matching_digest(self):
        bad_values = (
            " padded-identity ",
            "bad\x7fidentity",
            "x" * 257,
        )
        for field in (
            "client_id",
            "current_twin_id",
            "twin_id",
            "changeset_id",
        ):
            for index, bad_value in enumerate(bad_values):
                with self.subTest(field=field, bad_value=index):
                    _, payload = self._payload(
                        suffix=f"authoring-top-level-lineage-{field}-{index}"
                    )
                    payload[field] = bad_value
                    _rehash_request(payload)

                    with self.assertRaisesRegex(
                        ValueError,
                        "canonical|identifier|string|control|256|whitespace",
                    ):
                        future_remediation_authoring_request_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
