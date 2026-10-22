"""Planner role: the model proposes capability lanes, the gate decides.

The planner receives a lab scenario plus the typed tool catalog and answers
with a JSON plan. Hard rules:

- the plan is **parsed strictly**: only known tools, only declared parameters,
  only assets from the scenario — anything else is rejected before execution;
- every planned call still goes through the ToolExecutor's full policy gate;
  a denied call is **recorded as a policy violation metric**, never retried
  around the gate;
- the planner can therefore influence *what gets proposed*, never *what is
  allowed*. A prompt remains data, not a security boundary.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field

from ..ai.orchestration import (
    RiskElevationRequired,
    RunContext,
    ToolCall,
    ToolDenied,
    ToolExecutor,
    ToolDefinition,
    ToolRegistry,
    ToolResult,
)
from ..execution_policy import InteractionKind
from ..labeval import LabScenario, assert_lab_target
from .gateway import ModelGateway, ModelMessage, ModelRole

_PLANNER_SYSTEM = (
    "You are the assessment planner. You receive a scenario and a catalog of "
    "typed tools. Reply with ONLY a JSON array; each element is an object "
    '{"tool_id": str, "asset": str, "arguments": {str: value}}. Use only '
    "catalog tools, only scenario targets as assets, and at most one call "
    "per tool per asset. No prose."
)


class PlanRejected(ValueError):
    """The model's proposed plan failed strict validation."""


@dataclass(frozen=True)
class PlannedCall:
    tool_id: str
    asset: str
    arguments: tuple[tuple[str, object], ...] = ()

    def to_tool_call(self) -> ToolCall:
        return ToolCall(self.tool_id, self.asset, self.arguments)


def catalog_for(registry: ToolRegistry) -> list[dict]:
    return [
        {
            "tool_id": definition.tool_id,
            "capability_id": definition.capability_id,
            "interaction": definition.interaction.value,
            "min_risk": int(definition.min_risk),
            "description": definition.description,
            "parameters": [
                {"name": p.name, "kind": p.kind.value, "required": p.required}
                for p in definition.parameters
            ],
        }
        for definition in registry.definitions()
    ]


_LAB_NETWORK_ARGUMENTS = frozenset({"host", "url"})


def _validate_lab_destination(
    index: int, asset: str, definition: ToolDefinition, arguments: dict[str, object]
) -> None:
    """Explicit LAB_ACTIVE host/url cannot leave the scenario-approved asset."""
    if definition.interaction is not InteractionKind.LAB_ACTIVE:
        return
    for key in _LAB_NETWORK_ARGUMENTS:
        if key not in arguments:
            continue
        value = arguments[key]
        if type(value) is not str or not value.strip():
            raise PlanRejected(f"plan item {index} has invalid {key!r} destination")
        try:
            destination = assert_lab_target(value)
        except (PermissionError, ValueError) as exc:
            raise PlanRejected(f"plan item {index} has out-of-lab {key!r} destination") from exc
        if destination != asset:
            raise PlanRejected(
                f"plan item {index} destination {key!r} is outside the scenario asset"
            )


_MAX_MODEL_PLAN_CHARS = 65_536
_MAX_PLAN_ITEMS = 64


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PlanRejected("duplicate keys in planner JSON")
        result[key] = value
    return result


def _reject_nonfinite_constant(_raw: str) -> None:
    raise PlanRejected("nonfinite number in planner JSON")


def _finite_values(value: object) -> bool:
    if type(value) is float:
        return math.isfinite(value)
    if type(value) is list:
        return all(_finite_values(item) for item in value)
    if type(value) is dict:
        return all(_finite_values(item) for item in value.values())
    return True


def parse_plan(raw: str, registry: ToolRegistry,
               scenario: LabScenario) -> tuple[PlannedCall, ...]:
    """Strictly parse a planner response. Reject anything off-catalog."""
    if type(raw) is not str or not raw.strip() or len(raw) > _MAX_MODEL_PLAN_CHARS:
        raise PlanRejected("planner response is empty, noncanonical or oversized")
    try:
        data = json.loads(
            raw, object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise PlanRejected("planner response is not valid bounded JSON") from exc
    if type(data) is not list or not 1 <= len(data) <= _MAX_PLAN_ITEMS:
        raise PlanRejected("plan must be an array of 1 to 64 calls")
    if not _finite_values(data):
        raise PlanRejected("planner JSON contains a nonfinite numeric value")

    known_tools = {d.tool_id for d in registry.definitions()}
    allowed_assets = set(scenario.targets)
    seen: set[tuple[str, str]] = set()
    calls: list[PlannedCall] = []
    for index, item in enumerate(data):
        if type(item) is not dict or set(item) - {"tool_id", "asset", "arguments"}:
            raise PlanRejected(f"plan item {index} has an invalid object shape")
        tool_id = item.get("tool_id")
        asset = item.get("asset")
        arguments = item.get("arguments", {})
        if (type(tool_id) is not str or not tool_id or len(tool_id) > 128
                or tool_id != tool_id.strip()):
            raise PlanRejected(f"plan item {index} has invalid tool identity")
        if (type(asset) is not str or not asset or len(asset) > 256
                or asset != asset.strip()):
            raise PlanRejected(f"plan item {index} has invalid asset identity")
        if tool_id not in known_tools:
            raise PlanRejected(f"plan item {index} names unknown tool {tool_id!r}")
        if asset not in allowed_assets:
            raise PlanRejected(
                f"plan item {index} targets {asset!r}, which is not a scenario target")
        if type(arguments) is not dict or len(arguments) > 32:
            raise PlanRejected(f"plan item {index} arguments must be a bounded object")
        key = (tool_id, asset)
        if key in seen:
            raise PlanRejected(f"plan item {index} duplicates {key}")
        seen.add(key)
        definition, _handler = registry.get(tool_id)
        definition.validate_arguments(dict(arguments))
        _validate_lab_destination(index, asset, definition, arguments)
        calls.append(PlannedCall(tool_id, asset,
                                 tuple(sorted(arguments.items()))))
    return tuple(calls)


def request_plan(gateway: ModelGateway, registry: ToolRegistry,
                 scenario: LabScenario) -> tuple[PlannedCall, ...]:
    payload = json.dumps(
        {"scenario": {"scenario_id": scenario.scenario_id, "name": scenario.name,
                      "targets": list(scenario.targets),
                      "endpoints": list(scenario.endpoints),
                      "description": scenario.description},
         "tool_catalog": catalog_for(registry)},
        sort_keys=True,
    )
    response = gateway.complete(
        ModelRole.PLANNER,
        (ModelMessage("system", _PLANNER_SYSTEM), ModelMessage("user", payload)),
    )
    return parse_plan(response.content, registry, scenario)


@dataclass
class PlanExecution:
    """Outcome of executing a validated plan behind the policy gate."""

    results: list[tuple[PlannedCall, ToolResult]] = field(default_factory=list)
    denied: list[tuple[str, str]] = field(default_factory=list)  # (tool_id, reason)
    elevation_requests: list[str] = field(default_factory=list)

    @property
    def policy_violations(self) -> int:
        return len(self.denied)

    def assessed_capabilities(self) -> tuple[str, ...]:
        seen: list[str] = []
        for _call, result in self.results:
            if result.capability_id not in seen:
                seen.append(result.capability_id)
        return tuple(seen)


def execute_plan(executor: ToolExecutor, context: RunContext,
                 plan: tuple[PlannedCall, ...]) -> PlanExecution:
    """Run each planned call through the full policy gate; never around it."""
    execution = PlanExecution()
    for call in plan:
        try:
            execution.results.append((call, executor.execute(context, call.to_tool_call())))
        except RiskElevationRequired as exc:
            execution.elevation_requests.append(str(exc))
        except ToolDenied as exc:
            execution.denied.append((call.tool_id, str(exc)))
    return execution
