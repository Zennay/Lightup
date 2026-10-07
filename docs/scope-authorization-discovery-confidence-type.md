# Passive-discovery confidence type integrity

Issue: #915

Pinned source owner: draft PR #175 exact head
`df9eac879bbe232cd1e50fd6e9dfe12ff38f8469`.

## Problem

`ProspectSignal.confidence` is annotated as `float`, but unauthorized
discovery admission currently validates only its numeric range.

Python booleans and integers therefore satisfy the same comparisons, and a
`float` subclass is also accepted. That lets non-canonical runtime metadata
enter a prospect profile even though the typed boundary says confidence is a
float.

## Required invariant

Before the confidence range is evaluated:

- `type(confidence) is float`;
- exact `0.0`, interior floats and `1.0` remain accepted;
- exact out-of-range floats remain rejected;
- bools, integers and float subclasses fail closed;
- rejection leaves the profile's signal collection unchanged;
- no coercion or polymorphic comparison repairs malformed input.

## Collision boundary

This branch adds one regression module and this document only.

PR #175 remains the production owner of `src/lightup/discovery.py` and its
existing exact-boolean unauthorized-discovery guard. No production source is
modified here.

The slice does not touch domain/state, scope, activation, execution policy,
ToolRegistry, web authorization, target-capable workers, evidence-remediation,
deployment, verdict or attack-path state.

## Safety

Offline passive-metadata authorization narrowing only. No active discovery,
DNS/network I/O, target interaction, scanning, capability execution,
remediation/retest execution or deployment.
