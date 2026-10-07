# Passive-discovery signal object identity

Issue: #916

Pinned source owner: draft PR #175 exact head
`df9eac879bbe232cd1e50fd6e9dfe12ff38f8469`.

## Problem

`ProspectProfile.add_signal()` delegates the unauthorized-discovery
authorization check to the supplied object's
`validate_for_unauthorized_discovery()` method without first requiring the
canonical outer runtime type.

That means a `ProspectSignal` subclass or a duck object can replace the
validator itself. A forged object can therefore claim private provenance and
target interaction while its no-op validator lets it enter the prospect
profile.

## Required invariant

At prospect admission:

- `type(signal) is ProspectSignal`;
- exact canonical public/non-interactive signals remain accepted;
- exact canonical non-public or interactive signals remain denied by their
  normal validator;
- subclasses and duck objects fail closed before caller-controlled validation
  runs;
- rejection leaves the profile signal collection unchanged.

## Collision boundary

This branch adds one regression module and this document only.

PR #175 retains all `src/lightup/discovery.py` source ownership and its
existing exact-boolean admission implementation. #915 separately covers the
runtime type of confidence metadata.

No domain/state, scope, activation, execution policy, ToolRegistry, web
authorization, target-capable worker, evidence-remediation, deployment, verdict
or attack-path source is modified.

## Safety

Offline passive-discovery admission narrowing only. No active discovery,
DNS/network I/O, target interaction, scanning, capability execution,
remediation/retest execution or deployment.
