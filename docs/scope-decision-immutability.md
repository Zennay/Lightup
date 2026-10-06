# Scope decisions are immutable value objects

Issue: #349

## Contract

A scope decision is an authorization result, not a mutable authority container. Once `ScopePolicy.decide()` returns a `ScopeDecision`, callers must not be able to widen or rewrite that decision in place.

The regression contract proves that:

- a denied decision cannot have `allowed`, `reason`, or `normalized_host` reassigned;
- an allowed decision is equally immutable;
- a failed mutation attempt leaves the original decision value unchanged;
- repeated evaluation returns equal but independent immutable value objects.

This proof intentionally does not treat arbitrary caller-constructed or `dataclasses.replace()`-produced decisions as trusted. Downstream coherence checks remain responsible for deciding whether externally supplied decision objects are authoritative.

## Collision boundary

This slice adds only one dedicated regression module and this document. It does not modify production source, existing tests/docs, planner/orchestrator, activation, execution policy, domain, webapp, or another active scope-authorization lane.

## Safety

Pure in-memory value-object proof only. No DNS/network I/O, target interaction, scanning, capability execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
