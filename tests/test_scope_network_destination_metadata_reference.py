"""Offline reference for trusted network-destination tool metadata.

This is a source-owner acceptance oracle only. It performs no network I/O and
does not grant authorization.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import unittest


class ReferenceParamKind(str, Enum):
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"


class DestinationRole(str, Enum):
    NONE = "none"
    HOST = "host"
    ENDPOINT = "endpoint"
    PORT = "port"
    PORT_SET = "port_set"


@dataclass(frozen=True)
class ParameterMetadata:
    name: str
    kind: ReferenceParamKind
    destination_role: DestinationRole = DestinationRole.NONE


@dataclass(frozen=True)
class DestinationMetadataIndex:
    host_names: frozenset[str]
    endpoint_names: frozenset[str]
    port_names: frozenset[str]
    port_set_names: frozenset[str]


_ROLE_KIND = {
    DestinationRole.HOST: ReferenceParamKind.STRING,
    DestinationRole.ENDPOINT: ReferenceParamKind.STRING,
    DestinationRole.PORT: ReferenceParamKind.INTEGER,
    DestinationRole.PORT_SET: ReferenceParamKind.STRING,
}


def validate_trusted_parameter_metadata(value: object) -> tuple[ParameterMetadata, ...] | None:
    """Return immutable validated metadata or None.

    A positive result only proves metadata shape/uniqueness. It is not a grant,
    approval, capability decision, scope decision, or execution permit.
    """
    if type(value) is not tuple:
        return None

    seen: set[str] = set()
    validated: list[ParameterMetadata] = []
    for item in value:
        if type(item) is not ParameterMetadata:
            return None
        if type(item.name) is not str or not item.name or item.name != item.name.strip():
            return None
        if len(item.name) > 128 or any(ord(ch) < 33 or ord(ch) == 127 for ch in item.name):
            return None
        if item.name in seen:
            return None
        seen.add(item.name)

        if type(item.kind) is not ReferenceParamKind:
            return None
        if type(item.destination_role) is not DestinationRole:
            return None

        expected_kind = _ROLE_KIND.get(item.destination_role)
        if expected_kind is not None and item.kind is not expected_kind:
            return None
        validated.append(item)

    return tuple(validated)


def trusted_destination_index(value: object) -> DestinationMetadataIndex | None:
    validated = validate_trusted_parameter_metadata(value)
    if validated is None:
        return None

    by_role = {
        role: frozenset(
            item.name for item in validated if item.destination_role is role
        )
        for role in (
            DestinationRole.HOST,
            DestinationRole.ENDPOINT,
            DestinationRole.PORT,
            DestinationRole.PORT_SET,
        )
    }
    return DestinationMetadataIndex(
        host_names=by_role[DestinationRole.HOST],
        endpoint_names=by_role[DestinationRole.ENDPOINT],
        port_names=by_role[DestinationRole.PORT],
        port_set_names=by_role[DestinationRole.PORT_SET],
    )


class NetworkDestinationMetadataReferenceTests(unittest.TestCase):
    def test_canonical_split_destination_metadata_is_indexed_by_role(self):
        metadata = (
            ParameterMetadata("host", ReferenceParamKind.STRING, DestinationRole.HOST),
            ParameterMetadata("url", ReferenceParamKind.STRING, DestinationRole.ENDPOINT),
            ParameterMetadata("port", ReferenceParamKind.INTEGER, DestinationRole.PORT),
            ParameterMetadata("ports", ReferenceParamKind.STRING, DestinationRole.PORT_SET),
            ParameterMetadata("path", ReferenceParamKind.STRING),
        )
        self.assertEqual(
            trusted_destination_index(metadata),
            DestinationMetadataIndex(
                host_names=frozenset({"host"}),
                endpoint_names=frozenset({"url"}),
                port_names=frozenset({"port"}),
                port_set_names=frozenset({"ports"}),
            ),
        )

    def test_empty_metadata_is_valid_and_grants_no_destination_names(self):
        self.assertEqual(
            trusted_destination_index(()),
            DestinationMetadataIndex(frozenset(), frozenset(), frozenset(), frozenset()),
        )

    def test_current_lab_tool_shapes_have_unambiguous_roles(self):
        tls = (
            ParameterMetadata("host", ReferenceParamKind.STRING, DestinationRole.HOST),
            ParameterMetadata("port", ReferenceParamKind.INTEGER, DestinationRole.PORT),
        )
        inventory = (
            ParameterMetadata("host", ReferenceParamKind.STRING, DestinationRole.HOST),
            ParameterMetadata("ports", ReferenceParamKind.STRING, DestinationRole.PORT_SET),
        )
        http = (
            ParameterMetadata("url", ReferenceParamKind.STRING, DestinationRole.ENDPOINT),
        )
        self.assertEqual(trusted_destination_index(tls).port_names, frozenset({"port"}))
        self.assertEqual(
            trusted_destination_index(inventory).port_set_names, frozenset({"ports"})
        )
        self.assertEqual(
            trusted_destination_index(http).endpoint_names, frozenset({"url"})
        )

    def test_caller_supplied_plain_name_set_is_not_registry_metadata(self):
        self.assertIsNone(trusted_destination_index(frozenset({"url"})))

    def test_list_container_is_rejected(self):
        self.assertIsNone(
            trusted_destination_index(
                [ParameterMetadata("url", ReferenceParamKind.STRING, DestinationRole.ENDPOINT)]
            )
        )

    def test_tuple_subclass_is_rejected(self):
        class EvilTuple(tuple):
            pass

        self.assertIsNone(
            trusted_destination_index(
                EvilTuple((ParameterMetadata("url", ReferenceParamKind.STRING),))
            )
        )

    def test_parameter_subclass_is_rejected(self):
        class EvilParameter(ParameterMetadata):
            pass

        self.assertIsNone(
            trusted_destination_index(
                (EvilParameter("url", ReferenceParamKind.STRING, DestinationRole.ENDPOINT),)
            )
        )

    def test_duplicate_parameter_names_fail_closed_even_across_roles(self):
        self.assertIsNone(
            trusted_destination_index(
                (
                    ParameterMetadata("target", ReferenceParamKind.STRING, DestinationRole.HOST),
                    ParameterMetadata("target", ReferenceParamKind.STRING, DestinationRole.ENDPOINT),
                )
            )
        )

    def test_blank_or_padded_names_fail_closed(self):
        for name in ("", " url", "url ", "ur\nl"):
            with self.subTest(name=name):
                self.assertIsNone(
                    trusted_destination_index(
                        (ParameterMetadata(name, ReferenceParamKind.STRING),)
                    )
                )

    def test_destination_role_must_be_exact_enum(self):
        forged = object.__new__(ParameterMetadata)
        object.__setattr__(forged, "name", "url")
        object.__setattr__(forged, "kind", ReferenceParamKind.STRING)
        object.__setattr__(forged, "destination_role", "endpoint")
        self.assertIsNone(trusted_destination_index((forged,)))

    def test_kind_must_be_exact_enum(self):
        forged = object.__new__(ParameterMetadata)
        object.__setattr__(forged, "name", "url")
        object.__setattr__(forged, "kind", "string")
        object.__setattr__(forged, "destination_role", DestinationRole.ENDPOINT)
        self.assertIsNone(trusted_destination_index((forged,)))

    def test_host_and_endpoint_roles_require_string_kind(self):
        for role in (DestinationRole.HOST, DestinationRole.ENDPOINT):
            with self.subTest(role=role):
                self.assertIsNone(
                    trusted_destination_index(
                        (ParameterMetadata("target", ReferenceParamKind.INTEGER, role),)
                    )
                )

    def test_scalar_port_role_requires_integer_kind(self):
        self.assertIsNone(
            trusted_destination_index(
                (ParameterMetadata("port", ReferenceParamKind.STRING, DestinationRole.PORT),)
            )
        )

    def test_port_set_role_requires_string_kind_for_current_registry_contract(self):
        self.assertIsNone(
            trusted_destination_index(
                (ParameterMetadata("ports", ReferenceParamKind.INTEGER, DestinationRole.PORT_SET),)
            )
        )

    def test_non_destination_metadata_does_not_gain_network_authority(self):
        metadata = (
            ParameterMetadata("note", ReferenceParamKind.STRING),
            ParameterMetadata("path", ReferenceParamKind.STRING),
        )
        self.assertEqual(
            trusted_destination_index(metadata),
            DestinationMetadataIndex(frozenset(), frozenset(), frozenset(), frozenset()),
        )

    def test_validation_is_input_pure(self):
        metadata = (
            ParameterMetadata("host", ReferenceParamKind.STRING, DestinationRole.HOST),
            ParameterMetadata("port", ReferenceParamKind.INTEGER, DestinationRole.PORT),
        )
        before = tuple(metadata)
        self.assertIsNotNone(trusted_destination_index(metadata))
        self.assertEqual(metadata, before)


if __name__ == "__main__":
    unittest.main()
