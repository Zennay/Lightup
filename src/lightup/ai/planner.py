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


def _validate_lab_network_argument_scope(
    index: int,
    asset: str,
    definition: ToolDefinition,
    arguments: dict[str, object],
) -> None:
    """Bind network-bearing LAB_ACTIVE arguments to the exact scenario asset."""
    if definition.interaction is not InteractionKind.LAB_ACTIVE:
        return
    for name in _LAB_NETWORK_ARGUMENTS:
        if name not in arguments:
            continue
        value = arguments[name]
        try:
            argument_asset = assert_lab_target(str(value))
        except (PermissionError, ValueError) as exc:
            raise PlanRejected(
                f"plan item {index} argument {name!r} is not an isolated lab target"
            ) from exc
        if argument_asset != asset:
            raise PlanRejected(
                f"plan item {index} argument {name!r} resolves to "
                f"{argument_asset!r}, not scenario asset {asset!r}"
            )


def parse_plan(raw: str, registry: ToolRegistry,
               scenario: LabScenario) -> tuple[PlannedCall, ...]:
    """Strictly parse a planner response. Reject anything off-catalog."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PlanRejected(f"plan is not valid JSON: {exc}") from exc
    if not isinstance(data, list) or not data:
        raise PlanRejected("plan must be a non-empty JSON array")

    known_tools = {d.tool_id for d in registry.definitions()}
    allowed_assets = set(scenario.targets)
    seen: set[tuple[str, str]] = set()
    calls: list[PlannedCall] = []
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise PlanRejected(f"plan item {index} is not an object")
        tool_id = item.get("tool_id")
        asset = item.get("asset")
        arguments = item.get("arguments", {})
        if tool_id not in known_tools:
            raise PlanRejected(f"plan item {index} names unknown tool {tool_id!r}")
        if asset not in allowed_assets:
            raise PlanRejected(
                f"plan item {index} targets {asset!r}, which is not a scenario target")
        if not isinstance(arguments, dict):
            raise PlanRejected(f"plan item {index} arguments must be an object")
        key = (str(tool_id), str(asset))
        if key in seen:
            raise PlanRejected(f"plan item {index} duplicates {key}")
        seen.add(key)
        definition, _handler = registry.get(str(tool_id))
        definition.validate_arguments(dict(arguments))
        _validate_lab_network_argument_scope(index, str(asset), definition, arguments)
        calls.append(PlannedCall(str(tool_id), str(asset),
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
