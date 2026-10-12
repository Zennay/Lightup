"""Synthetic, offline acceptance for #1158 receipt shape, no network activity."""
from __future__ import annotations

from dataclasses import replace
import unittest

from scope_1158_ingress_receipt_reference import (
    IngressReceiptRejected,
    SCENARIOS,
    SuppliedIngressReceipt,
    SyntheticRouteObservation,
    check_supplied_ingress_receipt,
)


def _receipt() -> SuppliedIngressReceipt:
    observations = []
    for name, fields in SCENARIOS.items():
        (
            method, path, route, status, writes,
            actor, csrf, logout, hint_names, hint_paths,
        ) = fields
        observations.append(
            SyntheticRouteObservation(
                scenario=name,
                request_method=method,
                request_path=path,
                forwarded_hint_names=hint_names,
                requested_hint_paths=hint_paths,
                backend_path=path,
                backend_route=route,
                response_status=status,
                durable_write_count=writes,
                actor_class=actor,
                csrf_valid=csrf,
                session_invalidated=logout,
            )
        )
    return SuppliedIngressReceipt(
        repository_head="a" * 64,
        loaded_config_sha256="b" * 64,
        backend_capture_sha256="c" * 64,
        nginx_version="nginx-1.0",
        gunicorn_version="gunicorn-1.0",
        environment_label="disposable-loopback-lab",
        observations=tuple(observations),
    )


def _change_case(receipt, scenario, **changes):
    cases = tuple(
        replace(item, **changes) if item.scenario == scenario else item
        for item in receipt.observations
    )
    return replace(receipt, observations=cases)


class SuppliedIngressReceiptReferenceTest(unittest.TestCase):
    def setUp(self):
        self.valid = _receipt()

    def assertRejected(self, receipt):
        with self.assertRaises(IngressReceiptRejected):
            check_supplied_ingress_receipt(receipt)

    def test_all_synthetic_controls_are_required_but_never_authorize(self):
        self.assertEqual(len(self.valid.observations), 12)
        self.assertIsNone(check_supplied_ingress_receipt(self.valid))

    def test_case_order_does_not_change_completeness(self):
        shuffled = replace(
            self.valid, observations=tuple(reversed(self.valid.observations))
        )
        self.assertIsNone(check_supplied_ingress_receipt(shuffled))

    def test_each_missing_case_is_refused_atomically(self):
        for observation in self.valid.observations:
            with self.subTest(scenario=observation.scenario):
                missing = replace(
                    self.valid,
                    observations=tuple(
                        item for item in self.valid.observations
                        if item.scenario != observation.scenario
                    ),
                )
                self.assertRejected(missing)

    def test_duplicate_cases_and_unknown_cases_fail(self):
        cases = self.valid.observations
        self.assertRejected(
            replace(self.valid, observations=cases[:-1] + (cases[0],))
        )
        self.assertRejected(
            replace(
                self.valid, observations=cases[:-1] +
                (replace(cases[-1], scenario="get:invented"),)
            )
        )

    def test_raw_hint_coverage_cannot_be_faked_by_status(self):
        for observation in self.valid.observations:
            if observation.forwarded_hint_names:
                with self.subTest(scenario=observation.scenario):
                    self.assertRejected(
                        _change_case(
                            self.valid, observation.scenario,
                            forwarded_hint_names=(),
                        )
                    )
                    self.assertRejected(
                        _change_case(
                            self.valid, observation.scenario,
                            forwarded_hint_names=("x-untrusted-forwarded",),
                        )
                    )

    def test_harmless_or_missing_path_hint_does_not_count_as_adversarial(self):
        self.assertRejected(
            _change_case(
                self.valid, "get:x-original-url",
                requested_hint_paths=("/nonexistent",),
            )
        )
        self.assertRejected(
            _change_case(
                self.valid, "post:unknown",
                requested_hint_paths=(),
            )
        )
        self.assertRejected(
            _change_case(
                self.valid, "get:conflicting",
                requested_hint_paths=("/clients",) * 7,
            )
        )

    def test_hints_and_paths_require_exact_builtins(self):
        class WrongString(str):
            pass

        self.assertRejected(
            _change_case(
                self.valid, "get:x-original-url",
                requested_hint_paths=[ "/clients" ],
            )
        )
        self.assertRejected(
            _change_case(
                self.valid, "get:x-original-url",
                requested_hint_paths=(WrongString("/clients"),),
            )
        )
        self.assertRejected(
            _change_case(
                self.valid, "get:x-original-url",
                requested_hint_paths=("/clients\\r\\nInjected: true",),
            )
        )

    def test_case_insensitive_raw_header_names_are_accepted(self):
        case = _change_case(
            self.valid, "get:x-original-url",
            forwarded_hint_names=("X-Original-URL",),
        )
        self.assertIsNone(check_supplied_ingress_receipt(case))

    def test_duplicate_header_name_variants_refused(self):
        case = _change_case(
            self.valid, "get:x-original-url",
            forwarded_hint_names=("X-Original-URL", "x-original-url"),
        )
        self.assertRejected(case)

    def test_backend_observed_path_must_match_original_wire_path(self):
        self.assertRejected(
            _change_case(
                self.valid, "get:x-original-uri", backend_path="/clients"
            )
        )
        self.assertRejected(
            _change_case(
                self.valid, "post:unknown", backend_path="/clients"
            )
        )

    def test_generic_403_does_not_substitute_for_unknown_route(self):
        self.assertRejected(
            _change_case(
                self.valid, "get:conflicting",
                response_status=403, backend_route="forbidden",
            )
        )
        self.assertRejected(
            _change_case(
                self.valid, "get:x-rewrite-url",
                response_status=403, backend_route="not_found",
            )
        )

    def test_cross_tenant_actor_and_denial_cannot_be_swapped(self):
        self.assertRejected(
            _change_case(
                self.valid, "get:foreign-tenant",
                response_status=200, backend_route="clients_list",
            )
        )
        self.assertRejected(
            _change_case(
                self.valid, "get:foreign-tenant", actor_class="operator"
            )
        )

    def test_no_partial_writes_even_when_status_is_correct(self):
        for scenario in ("get:x-original-url", "post:unknown", "get:foreign-tenant"):
            with self.subTest(scenario=scenario):
                self.assertRejected(
                    _change_case(
                        self.valid, scenario, durable_write_count=1
                    )
                )

    def test_authorized_positive_control_requires_one_write(self):
        self.assertRejected(
            _change_case(
                self.valid, "post:authorized", durable_write_count=0
            )
        )
        self.assertRejected(
            _change_case(
                self.valid, "post:authorized", response_status=403
            )
        )

    def test_logout_must_invalidate_session(self):
        self.assertRejected(
            _change_case(
                self.valid, "post:logout", session_invalidated=False
            )
        )

    def test_post_controls_require_synthetic_operator_and_valid_csrf(self):
        for scenario in ("post:unknown", "post:authorized", "post:logout"):
            with self.subTest(scenario=scenario):
                self.assertRejected(
                    _change_case(self.valid, scenario, csrf_valid=False)
                )
                self.assertRejected(
                    _change_case(self.valid, scenario, actor_class="anonymous")
                )

    def test_receipt_digests_are_exact_lowercase_sha256_shape(self):
        for field in (
            "repository_head", "loaded_config_sha256",
            "backend_capture_sha256",
        ):
            with self.subTest(field=field):
                self.assertRejected(replace(self.valid, **{field: "x" * 64}))
                self.assertRejected(replace(self.valid, **{field: "A" * 64}))
                self.assertRejected(replace(self.valid, **{field: False}))

    def test_invalid_or_nonisolated_environment_is_refused(self):
        for label in ("production", "remote-host", "", "disposable-loopback-lab/../../etc"):
            with self.subTest(label=label):
                self.assertRejected(replace(self.valid, environment_label=label))
        self.assertRejected(replace(self.valid, nginx_version=""))
        self.assertRejected(replace(self.valid, gunicorn_version="x" * 100))

    def test_polymorphic_containers_and_metadata_do_not_pass(self):
        class WrongString(str):
            pass

        class WrongCase(SyntheticRouteObservation):
            pass

        self.assertRejected(
            replace(self.valid, observations=list(self.valid.observations))
        )
        self.assertRejected(
            replace(
                self.valid, repository_head=WrongString("a" * 64)
            )
        )
        self.assertRejected(
            replace(
                self.valid,
                observations=(WrongCase(**vars(self.valid.observations[0])),)
                + self.valid.observations[1:],
            )
        )
        self.assertRejected(
            _change_case(
                self.valid, "get:x-original-url",
                forwarded_hint_names=[ "x-original-url" ],
            )
        )
        self.assertRejected(
            _change_case(
                self.valid, "post:authorized", durable_write_count=True
            )
        )

    def test_input_stays_unmodified_after_late_rejection(self):
        original = self.valid
        malformed = _change_case(
            original, "post:logout", backend_path="/clients"
        )
        self.assertRejected(malformed)
        self.assertEqual(self.valid, original)
        self.assertEqual(malformed.observations[-1].backend_path, "/clients")


if __name__ == "__main__":
    unittest.main()
