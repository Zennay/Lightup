"""Optional offline registry destination-role review; never authorizes or dispatches."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import math
import re
from urllib.parse import urlsplit

from .ai.orchestration import ParamKind, ToolDefinition, ToolParameter, ToolRegistry
from .execution_policy import InteractionKind
from .engagements import RiskLevel


class DestinationMetadataRefused(ValueError):
    def __init__(self):
        super().__init__("destination metadata refused")


class DestinationRole(Enum):
    HOST = "host"
    ENDPOINT = "endpoint"
    PORT = "port"
    PORT_SET = "port_set"


@dataclass(frozen=True, slots=True)
class DestinationField:
    parameter: str
    role: DestinationRole


@dataclass(frozen=True, slots=True)
class DestinationReview:
    destination_fields_checked: int
    status: str = field(init=False, default="hold")
    authorization_verified: bool = field(init=False, default=False)
    permit_issued: bool = field(init=False, default=False)
    execution_enabled: bool = field(init=False, default=False)
    release_approved: bool = field(init=False, default=False)


_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z", re.ASCII)
_DNS = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
_KINDS = {
    DestinationRole.HOST: ParamKind.STRING,
    DestinationRole.ENDPOINT: ParamKind.STRING,
    DestinationRole.PORT: ParamKind.INTEGER,
    DestinationRole.PORT_SET: ParamKind.STRING,
}


def _deny():
    raise DestinationMetadataRefused()


def _host(value):
    if type(value) is not str or not value or len(value) > 253 or value != value.lower():
        return False
    if any(ord(c) < 33 or ord(c) > 126 for c in value) or any(c in value for c in "\\/%@?#[]"):
        return False
    try:
        return ipaddress.ip_address(value).compressed == value
    except ValueError:
        pass
    parts = value.split(".")
    if (value.isdecimal()
            or (len(parts) > 1 and all(p.isdecimal() for p in parts))
            or any(p.startswith("0x") and len(p) > 2
                   and all(c in "0123456789abcdef" for c in p[2:]) for p in parts)):
        return False  # reject ambiguous alternate numeric-host spellings
    return all(_DNS.fullmatch(part) for part in parts)


def _endpoint(value):
    if type(value) is not str or not value or len(value) > 2048:
        return False
    # An endpoint identity must be a canonical ASCII URI; require explicit
    # percent encoding of Unicode paths rather than parser normalization.
    if any(ord(c) < 33 or ord(c) > 126 for c in value) or "\\" in value:
        return False
    try:
        p = urlsplit(value)
        if (p.scheme not in ("http", "https") or not p.netloc or p.username is not None
                or p.password is not None or p.fragment or "%" in p.netloc or "@" in p.netloc
                or p.hostname is None or not _host(p.hostname)):
            return False
        host = p.hostname
        if ":" in host:
            if not p.netloc.startswith("[" + host + "]"):
                return False
            suffix = p.netloc[len(host) + 2:]
        else:
            if not p.netloc.startswith(host):
                return False
            suffix = p.netloc[len(host):]
        if suffix:
            if not re.fullmatch(r":[1-9][0-9]{0,4}", suffix, re.ASCII):
                return False
            port = p.port
            if port is None or not 1 <= port <= 65535:
                return False
        return True
    except (ValueError, TypeError):
        return False


def _ports(value):
    if type(value) is not str or not value or len(value) > 95:
        return False
    parts = value.split(",")
    if len(parts) > 16:
        return False
    last = 0
    for part in parts:
        if not re.fullmatch(r"[1-9][0-9]{0,4}", part, re.ASCII):
            return False
        n = int(part)
        if n <= last or n > 65535:
            return False
        last = n
    return True


def _typed(kind, value):
    if kind is ParamKind.STRING:
        return type(value) is str and len(value) <= 2048
    if kind is ParamKind.INTEGER:
        return type(value) is int and -(2 ** 63) <= value < 2 ** 63
    if kind is ParamKind.NUMBER:
        return (type(value) is int and -(2 ** 63) <= value < 2 ** 63) or (
            type(value) is float and math.isfinite(value))
    if kind is ParamKind.BOOLEAN:
        return type(value) is bool
    return False


@dataclass(frozen=True, slots=True)
class TrustedDestinationManifest:
    """Code-owned definition shape only. NOT grant, asset binding or permission."""
    _registry: ToolRegistry
    _definition: ToolDefinition
    _fields: tuple[DestinationField, ...]
    _parameters: tuple[ToolParameter, ...]
    _handler: object
    _snapshot: tuple
    _registry_map: dict
    _definition_snapshot: tuple
    _roles_snapshot: tuple

    def __init__(self, registry, definition, fields):
        if type(registry) is not ToolRegistry or type(definition) is not ToolDefinition or type(fields) is not tuple:
            _deny()
        if (type(definition.tool_id) is not str or not _NAME.fullmatch(definition.tool_id)
                or type(definition.capability_id) is not str or not definition.capability_id
                or len(definition.capability_id) > 128
                or type(definition.description) is not str or len(definition.description) > 4096
                or type(definition.min_risk) is not RiskLevel):
            _deny()
        if type(registry._tools) is not dict:
            _deny()
        entry = registry._tools.get(definition.tool_id)
        if type(entry) is not tuple or len(entry) != 2 or entry[0] is not definition:
            _deny()
        if type(definition.interaction) is not InteractionKind or definition.interaction not in (
            InteractionKind.LAB_ACTIVE, InteractionKind.TARGET_ACTIVE
        ):
            _deny()
        params = definition.parameters
        if type(params) is not tuple or not 1 <= len(params) <= 64:
            _deny()
        registered = {}
        for p in params:
            if (type(p) is not ToolParameter or type(p.name) is not str or not _NAME.fullmatch(p.name)
                    or p.name in registered or type(p.kind) is not ParamKind or type(p.required) is not bool
                    or type(p.description) is not str or len(p.description) > 4096):
                _deny()
            registered[p.name] = p
        if not 1 <= len(fields) <= 4:
            _deny()
        roles = {}
        for f in fields:
            if (type(f) is not DestinationField or type(f.parameter) is not str
                    or type(f.role) is not DestinationRole or f.parameter in roles):
                _deny()
            p = registered.get(f.parameter)
            if p is None or p.required is not True or p.kind is not _KINDS[f.role]:
                _deny()
            roles[f.parameter] = f.role
        kinds = set(roles.values())
        # One trusted field per role: two HOST or two PORT selectors are
        # ambiguous even if their parameter names are distinct.
        if len(kinds) != len(fields):
            _deny()
        if (DestinationRole.HOST in kinds) == (DestinationRole.ENDPOINT in kinds):
            _deny()
        if DestinationRole.ENDPOINT in kinds and len(kinds) != 1:
            _deny()
        if DestinationRole.PORT in kinds and DestinationRole.PORT_SET in kinds:
            _deny()
        for k, v in (("_registry", registry), ("_definition", definition), ("_fields", fields),
                     ("_parameters", params), ("_handler", entry[1]),
                     ("_snapshot", tuple((p, p.name, p.kind, p.required, p.description) for p in params)),
                     ("_registry_map", registry._tools),
                     ("_definition_snapshot", (definition.tool_id, definition.capability_id,
                                               definition.interaction, definition.min_risk,
                                               definition.description, definition.parameters)),
                     ("_roles_snapshot", tuple((f, f.parameter, f.role) for f in fields))):
            object.__setattr__(self, k, v)

    def review(self, arguments):
        registry, definition = self._registry, self._definition
        if (type(registry._tools) is not dict or registry._tools is not self._registry_map
                or type(definition.tool_id) is not str):
            _deny()
        # A forged tuple's elements may run arbitrary __eq__ during snapshot
        # comparison; refuse replacement by identity before any comparisons.
        if type(self._fields) is not tuple or definition.parameters is not self._parameters:
            _deny()
        if (type(definition.capability_id) is not str
                or type(definition.interaction) is not InteractionKind
                or type(definition.min_risk) is not RiskLevel
                or type(definition.description) is not str
                or type(definition.parameters) is not tuple):
            _deny()
        if (definition.tool_id, definition.capability_id, definition.interaction,
                definition.min_risk, definition.description, definition.parameters) != self._definition_snapshot:
            _deny()
        if (len(self._fields) != len(self._roles_snapshot) or any(
                type(f) is not DestinationField or f is not original
                or type(f.parameter) is not str
                or f.parameter != name or f.role is not role
                for f, (original, name, role) in zip(self._fields, self._roles_snapshot))):
            _deny()
        entry = registry._tools.get(definition.tool_id)
        if (type(entry) is not tuple or len(entry) != 2 or entry[0] is not definition
                or entry[1] is not self._handler or definition.parameters is not self._parameters):
            _deny()
        if any(type(p.name) is not str or type(p.kind) is not ParamKind
               or type(p.required) is not bool or type(p.description) is not str
               or (p.name, p.kind, p.required, p.description) != (name, kind, required, description)
               for p, name, kind, required, description in self._snapshot):
            _deny()
        if type(arguments) is not dict or len(arguments) > 64:
            _deny()
        expected = {p.name: p for p in self._parameters}
        if any(type(name) is not str or name not in expected for name in arguments):
            _deny()
        for p in self._parameters:
            if p.name not in arguments:
                if p.required:
                    _deny()
                continue
            if not _typed(p.kind, arguments[p.name]):
                _deny()
        for field in self._fields:
            value = arguments[field.parameter]
            role = field.role
            if role is DestinationRole.HOST and not _host(value):
                _deny()
            if role is DestinationRole.ENDPOINT and not _endpoint(value):
                _deny()
            if role is DestinationRole.PORT and not 1 <= value <= 65535:
                _deny()
            if role is DestinationRole.PORT_SET and not _ports(value):
                _deny()
        return DestinationReview(destination_fields_checked=len(self._fields))
