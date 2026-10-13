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


if __name__ == "__main__":
    unittest.main()
