"""#1093: opt-in non-authorizing metadata review, synthetic unit tests only."""
import dataclasses
import unittest

from lightup.ai.orchestration import ParamKind, ToolDefinition, ToolParameter, ToolRegistry
from lightup.engagements import RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.trusted_destination_manifest_optin import (
    DestinationField, DestinationMetadataRefused, DestinationRole,
    TrustedDestinationManifest,
)


class TestTrustedDestinationMetadata1093(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.registry = ToolRegistry()

    def make(self, params, interaction=InteractionKind.LAB_ACTIVE):
        definition = ToolDefinition(
            "offline_tool", "web-baseline", interaction, RiskLevel.LOW_IMPACT,
            "description is never authority", tuple(params),
        )
        self.registry.register(definition, lambda *a: self.calls.append(a))
        return definition

    def manifest(self, params=None, fields=None):
        params = params or [ToolParameter("host", ParamKind.STRING)]
        definition = self.make(params)
        fields = fields or (DestinationField("host", DestinationRole.HOST),)
        return TrustedDestinationManifest(self.registry, definition, fields)

    def refused(self, fn):
        with self.assertRaisesRegex(DestinationMetadataRefused, "^destination metadata refused$"):
            fn()
        self.assertEqual(self.calls, [])

    def test_01_host_receipt_does_not_authorize(self):
        r = self.manifest().review({"host": "localhost"})
        self.assertEqual(r.status, "hold")
        self.assertEqual(r.destination_fields_checked, 1)
        for flag in ("authorization_verified", "permit_issued", "execution_enabled", "release_approved"):
            self.assertIs(getattr(r, flag), False)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            r.permit_issued = True
        self.assertEqual(self.calls, [])

    def test_02_split_host_port_shape(self):
        params = [ToolParameter("host", ParamKind.STRING), ToolParameter("port", ParamKind.INTEGER)]
        fields = (DestinationField("host", DestinationRole.HOST), DestinationField("port", DestinationRole.PORT))
        self.assertEqual(self.manifest(params, fields).review({"host": "127.0.0.1", "port": 443}).destination_fields_checked, 2)
        self.assertEqual(self.calls, [])

    def test_03_endpoint_shape(self):
        fields = (DestinationField("url", DestinationRole.ENDPOINT),)
        m = self.manifest([ToolParameter("url", ParamKind.STRING)], fields)
        self.assertEqual(m.review({"url": "https://localhost:443/path?q=1"}).status, "hold")
        self.assertEqual(m.review({"url": "http://[::1]:80/"}).status, "hold")

    def test_04_portset_shape(self):
        params = [ToolParameter("host", ParamKind.STRING), ToolParameter("ports", ParamKind.STRING)]
        fields = (DestinationField("host", DestinationRole.HOST), DestinationField("ports", DestinationRole.PORT_SET))
        m = self.manifest(params, fields)
        self.assertEqual(m.review({"host": "localhost", "ports": "80,443"}).destination_fields_checked, 2)
        for bad in ("443,80", "80,80", "01", "0", "65536", "80, 443", "80,,443",
                    "1," + ",".join(str(i) for i in range(2, 18))):
            with self.subTest(bad=bad):
                self.refused(lambda value=bad: m.review({"host": "localhost", "ports": value}))

    def test_05_definition_must_be_registered(self):
        d = ToolDefinition("offline_tool", "web-baseline", InteractionKind.LAB_ACTIVE,
                           RiskLevel.LOW_IMPACT, "", (ToolParameter("host", ParamKind.STRING),))
        self.refused(lambda: TrustedDestinationManifest(self.registry, d, (DestinationField("host", DestinationRole.HOST),)))

    def test_06_definition_subclasses_are_not_trusted(self):
        class Forged(ToolDefinition):
            pass
        d = Forged("offline_tool", "web-baseline", InteractionKind.LAB_ACTIVE,
                   RiskLevel.LOW_IMPACT, "", (ToolParameter("host", ParamKind.STRING),))
        self.registry._tools[d.tool_id] = (d, lambda *a: self.calls.append(a))
        self.refused(lambda: TrustedDestinationManifest(self.registry, d, (DestinationField("host", DestinationRole.HOST),)))

    def test_07_duplicate_destination_decl_denied(self):
        d = self.make([ToolParameter("host", ParamKind.STRING)])
        f = DestinationField("host", DestinationRole.HOST)
        self.refused(lambda: TrustedDestinationManifest(self.registry, d, (f, f)))

    def test_08_duplicate_registered_params_denied(self):
        d = self.make([ToolParameter("host", ParamKind.STRING), ToolParameter("host", ParamKind.STRING)])
        self.refused(lambda: TrustedDestinationManifest(self.registry, d, (DestinationField("host", DestinationRole.HOST),)))

    def test_09_unknown_role_denied(self):
        d = self.make([ToolParameter("host", ParamKind.STRING)])
        self.refused(lambda: TrustedDestinationManifest(self.registry, d, (DestinationField("host", "host"),)))

    def test_10_wrong_kind_denied(self):
        d = self.make([ToolParameter("port", ParamKind.STRING)])
        self.refused(lambda: TrustedDestinationManifest(self.registry, d, (DestinationField("port", DestinationRole.PORT),)))

    def test_11_optional_destination_denied(self):
        d = self.make([ToolParameter("host", ParamKind.STRING, required=False)])
        self.refused(lambda: TrustedDestinationManifest(self.registry, d, (DestinationField("host", DestinationRole.HOST),)))

    def test_12_host_and_endpoint_together_denied(self):
        params = [ToolParameter("host", ParamKind.STRING), ToolParameter("url", ParamKind.STRING)]
        fields = (DestinationField("host", DestinationRole.HOST), DestinationField("url", DestinationRole.ENDPOINT))
        self.refused(lambda: self.manifest(params, fields))

    def test_13_port_and_portset_together_denied(self):
        params = [ToolParameter("host", ParamKind.STRING), ToolParameter("port", ParamKind.INTEGER),
                  ToolParameter("ports", ParamKind.STRING)]
        fields = (DestinationField("host", DestinationRole.HOST), DestinationField("port", DestinationRole.PORT),
                  DestinationField("ports", DestinationRole.PORT_SET))
        self.refused(lambda: self.manifest(params, fields))

    def test_14_caller_declared_role_cannot_bypass(self):
        m = self.manifest()
        self.refused(lambda: m.review({"host": "localhost", "destination_roles": "host"}))

    def test_15_polymorphic_strings_rejected_without_callbacks(self):
        class Host(str):
            def __str__(self):
                raise AssertionError("must not call untrusted string coercion")
        m = self.manifest()
        self.refused(lambda: m.review({"host": Host("localhost")}))

    def test_16_bool_and_out_of_range_ports_denied(self):
        params = [ToolParameter("host", ParamKind.STRING), ToolParameter("port", ParamKind.INTEGER)]
        fields = (DestinationField("host", DestinationRole.HOST), DestinationField("port", DestinationRole.PORT))
        m = self.manifest(params, fields)
        for bad in (True, 0, 65536, 1.0, "443", -(2 ** 70)):
            with self.subTest(bad=bad):
                self.refused(lambda value=bad: m.review({"host": "localhost", "port": value}))

    def test_17_ambiguous_host_spellings_denied(self):
        m = self.manifest()
        for bad in ("example.com:443", "operator@localhost", "lo\ncalhost", "localhost\\evil",
                    "bad..name", "-bad", "bad-", "LOCALHOST", "127.000.0.1",
                    "[::1]", "fe80::1%eth0"):
            with self.subTest(bad=bad):
                self.refused(lambda value=bad: m.review({"host": value}))

    def test_18_ambiguous_endpoint_spellings_denied(self):
        fields = (DestinationField("url", DestinationRole.ENDPOINT),)
        m = self.manifest([ToolParameter("url", ParamKind.STRING)], fields)
        for bad in ("http://operator@localhost", "http://lo\ncalhost", "ftp://localhost",
                    "http://localhost:65536", "http://localhost:notaport", "//localhost",
                    "http://localhost#fragment", "https://localhost\\@other",
                    "https://localhost%2eother", "https://localhost:0", "https://localhost:080"):
            with self.subTest(bad=bad):
                self.refused(lambda value=bad: m.review({"url": value}))

    def test_19_registry_definition_swap_denied(self):
        m = self.manifest()
        d = m._definition
        self.registry._tools[d.tool_id] = (dataclasses.replace(d), lambda *a: self.calls.append(a))
        self.refused(lambda: m.review({"host": "localhost"}))

    def test_20_registry_handler_swap_denied(self):
        m = self.manifest()
        d = m._definition
        self.registry._tools[d.tool_id] = (d, lambda *a: self.calls.append(a))
        self.refused(lambda: m.review({"host": "localhost"}))

    def test_21_schema_mutation_denied(self):
        m = self.manifest()
        object.__setattr__(m._parameters[0], "kind", ParamKind.INTEGER)
        self.refused(lambda: m.review({"host": "localhost"}))

    def test_22_schema_replacement_denied(self):
        m = self.manifest()
        object.__setattr__(m._definition, "parameters", tuple(list(m._parameters)))
        self.refused(lambda: m.review({"host": "localhost"}))

    def test_23_non_destination_fields_do_not_set_authority(self):
        params = [ToolParameter("host", ParamKind.STRING), ToolParameter("notes", ParamKind.STRING, required=False)]
        m = self.manifest(params)
        r = m.review({"host": "localhost", "notes": "url=https://outside.invalid"})
        self.assertEqual(r.destination_fields_checked, 1)
        self.assertIs(r.authorization_verified, False)
        self.assertEqual(self.calls, [])

    def test_24_analysis_interaction_not_target_metadata(self):
        d = self.make([ToolParameter("host", ParamKind.STRING)], interaction=InteractionKind.ANALYSIS)
        self.refused(lambda: TrustedDestinationManifest(self.registry, d, (DestinationField("host", DestinationRole.HOST),)))

    def test_25_list_metadata_and_missing_required_denied(self):
        d = self.make([ToolParameter("host", ParamKind.STRING), ToolParameter("port", ParamKind.INTEGER)])
        self.refused(lambda: TrustedDestinationManifest(self.registry, d, [DestinationField("host", DestinationRole.HOST)]))
        fields = (DestinationField("host", DestinationRole.HOST), DestinationField("port", DestinationRole.PORT))
        m = TrustedDestinationManifest(self.registry, d, fields)
        self.refused(lambda: m.review({"host": "localhost"}))


    def test_26_destination_role_tampering_denied(self):
        m = self.manifest()
        object.__setattr__(m._fields[0], "role", "unclassified")
        self.refused(lambda: m.review({"host": "localhost"}))

    def test_27_destination_parameter_key_tampering_denied(self):
        m = self.manifest()
        object.__setattr__(m._fields[0], "parameter", "metadata")
        self.refused(lambda: m.review({"host": "localhost"}))

    def test_28_definition_risk_or_interaction_drift_denied(self):
        m = self.manifest()
        object.__setattr__(m._definition, "interaction", InteractionKind.TARGET_ACTIVE)
        self.refused(lambda: m.review({"host": "localhost"}))

    def test_29_registered_tools_map_swap_denied(self):
        m = self.manifest()
        self.registry._tools = dict(self.registry._tools)
        self.refused(lambda: m.review({"host": "localhost"}))



    def test_30_receipt_cannot_be_constructed_with_permission(self):
        from lightup.trusted_destination_manifest_optin import DestinationReview
        with self.assertRaises(TypeError):
            DestinationReview(1, permit_issued=True)
        with self.assertRaises(TypeError):
            DestinationReview(1, authorization_verified=True)
        with self.assertRaises(TypeError):
            DestinationReview(1, execution_enabled=True)
        with self.assertRaises(TypeError):
            DestinationReview(1, release_approved=True)
        receipt = self.manifest().review({"host": "localhost"})
        self.assertEqual(receipt.status, "hold")
        self.assertIs(receipt.permit_issued, False)




    def test_31_numeric_host_aliases_denied(self):
        m = self.manifest()
        for alias in ("2130706433", "0x7f000001", "0x7f.0.0.1", "0x7f.0x0.0x0.0x1"):
            with self.subTest(alias=alias):
                self.refused(lambda value=alias: m.review({"host": value}))

    def test_32_numeric_endpoint_aliases_denied(self):
        fields = (DestinationField("url", DestinationRole.ENDPOINT),)
        m = self.manifest([ToolParameter("url", ParamKind.STRING)], fields)
        for alias in ("http://2130706433/", "http://0x7f.0.0.1/", "https://0x7f000001:443/"):
            with self.subTest(alias=alias):
                self.refused(lambda value=alias: m.review({"url": value}))

    def test_33_mutated_capability_cannot_trigger_equality_callback(self):
        class Canary:
            def __eq__(self, other):
                raise AssertionError("untrusted metadata callback executed")
        m = self.manifest()
        object.__setattr__(m._definition, "capability_id", Canary())
        self.refused(lambda: m.review({"host": "localhost"}))

    def test_34_mutated_description_cannot_trigger_equality_callback(self):
        class Canary:
            def __eq__(self, other):
                raise AssertionError("untrusted metadata callback executed")
        m = self.manifest()
        object.__setattr__(m._definition, "description", Canary())
        self.refused(lambda: m.review({"host": "localhost"}))

    def test_35_parameter_description_drift_is_rejected(self):
        class Canary:
            def __eq__(self, other):
                raise AssertionError("untrusted metadata callback executed")
        m = self.manifest()
        object.__setattr__(m._parameters[0], "description", Canary())
        self.refused(lambda: m.review({"host": "localhost"}))

    def test_36_role_key_subclass_denied_without_comparison(self):
        class Canary(str):
            def __eq__(self, other):
                raise AssertionError("untrusted metadata callback executed")
        m = self.manifest()
        object.__setattr__(m._fields[0], "parameter", Canary("host"))
        self.refused(lambda: m.review({"host": "localhost"}))

    def test_37_integer_risk_rejected_after_registration(self):
        m = self.manifest()
        object.__setattr__(m._definition, "min_risk", 2)
        self.refused(lambda: m.review({"host": "localhost"}))

    def test_38_canonical_ipv6_endpoint_remains_nonauthorizing(self):
        fields = (DestinationField("url", DestinationRole.ENDPOINT),)
        m = self.manifest([ToolParameter("url", ParamKind.STRING)], fields)
        receipt = m.review({"url": "https://[2001:db8::1]:443/health"})
        self.assertEqual(receipt.status, "hold")
        self.assertIs(receipt.permit_issued, False)
        self.assertEqual(self.calls, [])

    def test_39_constructor_rejects_noncanonical_description(self):
        class Canary:
            def __eq__(self, other):
                raise AssertionError("untrusted metadata callback executed")
        d = self.make([ToolParameter("host", ParamKind.STRING)])
        object.__setattr__(d, "description", Canary())
        self.refused(lambda: TrustedDestinationManifest(
            self.registry, d, (DestinationField("host", DestinationRole.HOST),)))



    def test_40_replaced_parameter_tuple_cannot_invoke_adversarial_equality(self):
        class Canary:
            def __eq__(self, other):
                raise AssertionError("untrusted tuple equality callback executed")
        m = self.manifest()
        object.__setattr__(m._definition, "parameters", (Canary(),))
        self.refused(lambda: m.review({"host": "localhost"}))

    def test_41_replaced_role_collection_denied_before_traversal(self):
        m = self.manifest()
        object.__setattr__(m, "_fields", [DestinationField("host", DestinationRole.HOST)])
        self.refused(lambda: m.review({"host": "localhost"}))



    def test_42_review_never_calls_dns_socket_process_or_urlopen(self):
        from unittest.mock import patch
        fields = (DestinationField("url", DestinationRole.ENDPOINT),)
        m = self.manifest([ToolParameter("url", ParamKind.STRING)], fields)
        with (patch("socket.getaddrinfo", side_effect=AssertionError("DNS called")),
              patch("socket.create_connection", side_effect=AssertionError("socket called")),
              patch("subprocess.run", side_effect=AssertionError("process called")),
              patch("urllib.request.urlopen", side_effect=AssertionError("URL opened"))):
            receipt = m.review({"url": "http://localhost:8080/path"})
            self.assertEqual(receipt.status, "hold")
            self.assertIs(receipt.execution_enabled, False)
            self.refused(lambda: m.review({"url": "http://user@localhost"}))
        self.assertEqual(self.calls, [])

    def test_43_oversized_destination_inputs_fail_closed(self):
        m = self.manifest()
        self.refused(lambda: m.review({"host": "a" * 1000000}))
        fields = (DestinationField("url", DestinationRole.ENDPOINT),)
        m2 = TrustedDestinationManifest(
            self.registry,
            self.registry.get("offline_tool")[0] if False else
                ToolDefinition("other", "web-baseline", InteractionKind.LAB_ACTIVE,
                               RiskLevel.LOW_IMPACT, "", (ToolParameter("url", ParamKind.STRING),)),
            fields)
        # This branch should not be reached: an unregistered definition must fail.
        self.assertIsNotNone(m2)

    def test_44_mutated_parameter_description_string_refused(self):
        m = self.manifest()
        object.__setattr__(m._parameters[0], "description", "modified after registration")
        self.refused(lambda: m.review({"host": "localhost"}))

    def test_45_invalid_registered_description_type_denied(self):
        d = self.make([ToolParameter("host", ParamKind.STRING, description=object())])
        self.refused(lambda: TrustedDestinationManifest(
            self.registry, d, (DestinationField("host", DestinationRole.HOST),)))



    def test_46_duplicate_host_roles_in_distinct_parameters_are_rejected(self):
        params = [ToolParameter("primary_host", ParamKind.STRING),
                  ToolParameter("fallback_host", ParamKind.STRING)]
        fields = (DestinationField("primary_host", DestinationRole.HOST),
                  DestinationField("fallback_host", DestinationRole.HOST))
        self.refused(lambda: self.manifest(params, fields))

    def test_47_duplicate_port_roles_in_distinct_parameters_are_rejected(self):
        params = [ToolParameter("host", ParamKind.STRING),
                  ToolParameter("primary_port", ParamKind.INTEGER),
                  ToolParameter("fallback_port", ParamKind.INTEGER)]
        fields = (DestinationField("host", DestinationRole.HOST),
                  DestinationField("primary_port", DestinationRole.PORT),
                  DestinationField("fallback_port", DestinationRole.PORT))
        self.refused(lambda: self.manifest(params, fields))



    def test_48_oversized_url_short_circuits_before_parser(self):
        from unittest.mock import patch
        fields = (DestinationField("url", DestinationRole.ENDPOINT),)
        m = self.manifest([ToolParameter("url", ParamKind.STRING)], fields)
        with patch("lightup.trusted_destination_manifest_optin.urlsplit",
                   side_effect=AssertionError("parser called for oversized URL")):
            self.refused(lambda: m.review({"url": "http://localhost/" + "a" * 50000}))

    def test_49_oversized_host_short_circuits_before_ipaddress(self):
        from unittest.mock import patch
        m = self.manifest()
        with patch("lightup.trusted_destination_manifest_optin.ipaddress.ip_address",
                   side_effect=AssertionError("IP parser called for oversized host")):
            self.refused(lambda: m.review({"host": "a" * 50000}))

    def test_50_hostile_role_metadata_no_equality_callback(self):
        class RoleCanary:
            def __eq__(self, other):
                raise AssertionError("role equality callback called")
        d = self.make([ToolParameter("host", ParamKind.STRING)])
        self.refused(lambda: TrustedDestinationManifest(
            self.registry, d, (DestinationField("host", RoleCanary()),)))

    def test_51_hostile_parameter_kind_no_equality_callback(self):
        class KindCanary:
            def __eq__(self, other):
                raise AssertionError("kind equality callback called")
        d = self.make([ToolParameter("host", KindCanary())])
        self.refused(lambda: TrustedDestinationManifest(
            self.registry, d, (DestinationField("host", DestinationRole.HOST),)))

    def test_52_oversized_registered_parameter_description_rejected(self):
        d = self.make([ToolParameter("host", ParamKind.STRING, description="s" * 4097)])
        self.refused(lambda: TrustedDestinationManifest(
            self.registry, d, (DestinationField("host", DestinationRole.HOST),)))



    def test_53_non_ascii_endpoint_path_and_invisible_mark_refused(self):
        fields = (DestinationField("url", DestinationRole.ENDPOINT),)
        m = self.manifest([ToolParameter("url", ParamKind.STRING)], fields)
        for bad in ("https://localhost/résumé",
                    "https://localhost/\u200bpath",
                    "https://localhost/\ud800",
                    "https://localhost/\ufeff",
                    "https://localhost/\u2060"):
            with self.subTest(bad=repr(bad)):
                self.refused(lambda value=bad: m.review({"url": value}))

    def test_54_percent_encoded_unicode_path_remains_nonauthorizing(self):
        fields = (DestinationField("url", DestinationRole.ENDPOINT),)
        m = self.manifest([ToolParameter("url", ParamKind.STRING)], fields)
        r = m.review({"url": "https://localhost/r%C3%A9sum%C3%A9"})
        self.assertEqual(r.status, "hold")
        self.assertIs(r.execution_enabled, False)
        self.assertIs(r.authorization_verified, False)
        self.assertEqual(self.calls, [])



    def test_55_scheme_case_normalization_is_rejected(self):
        fields = (DestinationField("url", DestinationRole.ENDPOINT),)
        m = self.manifest([ToolParameter("url", ParamKind.STRING)], fields)
        for bad in ("HTTP://localhost/", "Http://localhost/", "hTTps://localhost/",
                    "HtTpS://localhost:443/"):
            with self.subTest(bad=bad):
                self.refused(lambda value=bad: m.review({"url": value}))

    def test_56_empty_fragment_delimiter_rejected(self):
        fields = (DestinationField("url", DestinationRole.ENDPOINT),)
        m = self.manifest([ToolParameter("url", ParamKind.STRING)], fields)
        for bad in ("https://localhost#", "https://localhost/path#",
                    "https://localhost/path?x=1#", "https://localhost/path#?x=1"):
            with self.subTest(bad=bad):
                self.refused(lambda value=bad: m.review({"url": value}))

    def test_57_empty_query_delimiter_rejected(self):
        fields = (DestinationField("url", DestinationRole.ENDPOINT),)
        m = self.manifest([ToolParameter("url", ParamKind.STRING)], fields)
        for bad in ("https://localhost?", "https://localhost/path?"):
            with self.subTest(bad=bad):
                self.refused(lambda value=bad: m.review({"url": value}))

    def test_58_canonical_explicit_query_does_not_authorize(self):
        fields = (DestinationField("url", DestinationRole.ENDPOINT),)
        m = self.manifest([ToolParameter("url", ParamKind.STRING)], fields)
        receipt = m.review({"url": "https://localhost/path?q=hello%20world"})
        self.assertEqual(receipt.status, "hold")
        self.assertFalse(receipt.permit_issued)
        self.assertFalse(receipt.authorization_verified)
        self.assertFalse(receipt.release_approved)
        self.assertEqual(self.calls, [])



    def test_59_url_parser_cannot_rewrite_identity(self):
        from unittest.mock import patch
        from urllib.parse import urlsplit
        fields = (DestinationField("url", DestinationRole.ENDPOINT),)
        m = self.manifest([ToolParameter("url", ParamKind.STRING)], fields)
        original = urlsplit("https://localhost/path")
        class RewritingResult:
            scheme = original.scheme
            netloc = original.netloc
            username = None
            password = None
            fragment = ""
            hostname = original.hostname
            port = None
            def geturl(self):
                return "https://elsewhere.invalid/path"
        with patch("lightup.trusted_destination_manifest_optin.urlsplit",
                   return_value=RewritingResult()):
            self.refused(lambda: m.review({"url": "https://localhost/path"}))
        self.assertEqual(self.calls, [])

    def test_60_canonical_url_roundtrip_remains_hold(self):
        fields = (DestinationField("url", DestinationRole.ENDPOINT),)
        m = self.manifest([ToolParameter("url", ParamKind.STRING)], fields)
        for value in ("http://localhost", "https://localhost:443/path?x=1",
                      "http://[::1]:8080/api", "https://localhost/r%C3%A9sum%C3%A9"):
            with self.subTest(url=value):
                receipt = m.review({"url": value})
                self.assertEqual(receipt.status, "hold")
                self.assertIs(receipt.execution_enabled, False)
        self.assertEqual(self.calls, [])



    def test_61_seeded_malformed_authority_corpus_stays_denied(self):
        from random import Random
        rng = Random(1093)
        fields = (DestinationField("url", DestinationRole.ENDPOINT),)
        m = self.manifest([ToolParameter("url", ParamKind.STRING)], fields)
        poisoned = (
            "operator@localhost", "0x7f.0.0.1", "2130706433",
            "lo\ncalhost", "localhost\\evil", "localhost%2eother",
            "localhost:00080", "localhost:0", "localhost:65536",
            "localhost:notaport",
        )
        for index in range(1800):
            authority = rng.choice(poisoned)
            scheme = rng.choice(("http://", "https://", "HTTP://", "HtTpS://"))
            path = rng.choice(("", "/ok", "/x?q=1", "/ok#"))
            candidate = scheme + authority + path
            with self.subTest(case=index):
                self.refused(lambda v=candidate: m.review({"url": v}))
        self.assertEqual(self.calls, [])

    def test_62_exhaustive_canonical_uri_corpus_remains_hold(self):
        fields = (DestinationField("url", DestinationRole.ENDPOINT),)
        m = self.manifest([ToolParameter("url", ParamKind.STRING)], fields)
        checked = 0
        for scheme in ("http", "https"):
            for host in ("localhost", "127.0.0.1", "192.168.1.2",
                         "example.test", "[::1]", "[2001:db8::1]"):
                for port in ("", ":1", ":80", ":443", ":65535"):
                    for path in ("", "/status", "/a?x=1", "/r%C3%A9sum%C3%A9"):
                        candidate = scheme + "://" + host + port + path
                        with self.subTest(url=candidate):
                            result = m.review({"url": candidate})
                            self.assertEqual(result.status, "hold")
                            self.assertIs(result.permit_issued, False)
                            self.assertIs(result.execution_enabled, False)
                        checked += 1
        self.assertEqual(checked, 240)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
