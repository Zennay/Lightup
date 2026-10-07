# Canonical ParamKind tool-schema metadata

Issue: #913

This acceptance contract is pinned directly above active ToolRegistry owner
PR #156 exact head `e84f2cd74d24f143c02b38cc05cb1c4c64352966`.

## Problem

An exact ToolParameter can currently carry a non-canonical object in its
annotation-only `kind` field. Runtime argument validation later delegates
directly to `parameter.kind.accepts(value)`.

A duck object can therefore provide its own `accepts()` implementation and
replace the intended ParamKind type check while remaining nested in an
otherwise exact tool schema.

## Required invariant

At registry admission:

- every parameter kind is an actual `ParamKind` member;
- canonical enum members retain existing argument behavior;
- raw strings fail closed;
- duck/polymorphic objects with caller-controlled `accepts()` fail closed;
- rejected schemas never enter the registry.

## Collision boundary

Tests/docs only. PR #156 remains the production source owner.

This contract is separate from:
- #907 outer ToolDefinition identity;
- #911 parameter container/object identity;
- #908 exact boolean `required` metadata.

No execution-policy, domain/state, activation, worker, evidence-remediation,
remediation/retest execution, deployment, verdict or attack-path source is
changed.

## Safety

Offline typed-argument metadata validation only. No handler, network or target
interaction occurs.
