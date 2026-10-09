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
    NETWORK = "network"


@dataclass(frozen=True)
class ParameterMetadata:
    name: str
    kind: ReferenceParamKind
    destination_role: DestinationRole = DestinationRole.NONE


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
        if item.destination_role is DestinationRole.NETWORK and item.kind is not ReferenceParamKind.STRING:
            return None
        validated.append(item)

    return tuple(validated)


def trusted_network_parameter_names(value: object) -> frozenset[str] | None:
    validated = validate_trusted_parameter_metadata(value)
    if validated is None:
        return None
    return frozenset(
        item.name
        for item in validated
        if item.destination_role is DestinationRole.NETWORK
    )


class NetworkDestinationMetadataReferenceTests(unittest.TestCase):
    def test_canonical_metadata_yields_immutable_network_name_set(self):
        metadata = (
            ParameterMetadata("url", ReferenceParamKind.STRING, DestinationRole.NETWORK),
            ParameterMetadata("path", ReferenceParamKind.STRING),
        )
        self.assertEqual(trusted_network_parameter_names(metadata), frozenset({"url"}))

    def test_empty_metadata_is_valid_and_grants_no_destination_names(self):
        self.assertEqual(trusted_network_parameter_names(()), frozenset())

    def test_caller_supplied_plain_name_set_is_not_registry_metadata(self):
        self.assertIsNone(trusted_network_parameter_names(frozenset({"url"})))

    def test_list_container_is_rejected(self):
        self.assertIsNone(
            trusted_network_parameter_names(
                [ParameterMetadata("url", ReferenceParamKind.STRING, DestinationRole.NETWORK)]
            )
        )

    def test_tuple_subclass_is_rejected(self):
        class EvilTuple(tuple):
            pass

        self.assertIsNone(
            trusted_network_parameter_names(
                EvilTuple((ParameterMetadata("url", ReferenceParamKind.STRING),))
            )
        )

    def test_parameter_subclass_is_rejected(self):
        class EvilParameter(ParameterMetadata):
            pass

        self.assertIsNone(
            trusted_network_parameter_names(
                (EvilParameter("url", ReferenceParamKind.STRING, DestinationRole.NETWORK),)
            )
        )

    def test_duplicate_parameter_names_fail_closed(self):
        self.assertIsNone(
            trusted_network_parameter_names(
                (
                    ParameterMetadata("url", ReferenceParamKind.STRING, DestinationRole.NETWORK),
                    ParameterMetadata("url", ReferenceParamKind.STRING),
                )
            )
        )

    def test_blank_or_padded_names_fail_closed(self):
        for name in ("", " url", "url ", "ur\nl"):
            with self.subTest(name=name):
                self.assertIsNone(
                    trusted_network_parameter_names(
                        (ParameterMetadata(name, ReferenceParamKind.STRING),)
                    )
                )

    def test_destination_role_must_be_exact_enum(self):
        forged = object.__new__(ParameterMetadata)
        object.__setattr__(forged, "name", "url")
        object.__setattr__(forged, "kind", ReferenceParamKind.STRING)
        object.__setattr__(forged, "destination_role", "network")
        self.assertIsNone(trusted_network_parameter_names((forged,)))

    def test_kind_must_be_exact_enum(self):
        forged = object.__new__(ParameterMetadata)
        object.__setattr__(forged, "name", "url")
        object.__setattr__(forged, "kind", "string")
        object.__setattr__(forged, "destination_role", DestinationRole.NETWORK)
        self.assertIsNone(trusted_network_parameter_names((forged,)))

    def test_network_destination_parameter_must_be_string_typed(self):
        for kind in (ReferenceParamKind.INTEGER, ReferenceParamKind.BOOLEAN):
            with self.subTest(kind=kind):
                self.assertIsNone(
                    trusted_network_parameter_names(
                        (ParameterMetadata("target", kind, DestinationRole.NETWORK),)
                    )
                )

    def test_non_destination_string_metadata_does_not_gain_network_authority(self):
        metadata = (
            ParameterMetadata("note", ReferenceParamKind.STRING),
            ParameterMetadata("path", ReferenceParamKind.STRING),
        )
        self.assertEqual(trusted_network_parameter_names(metadata), frozenset())

    def test_validation_is_input_pure(self):
        metadata = (
            ParameterMetadata("host", ReferenceParamKind.STRING, DestinationRole.NETWORK),
            ParameterMetadata("port", ReferenceParamKind.INTEGER),
        )
        before = tuple(metadata)
        self.assertEqual(trusted_network_parameter_names(metadata), frozenset({"host"}))
        self.assertEqual(metadata, before)


if __name__ == "__main__":
    unittest.main()
