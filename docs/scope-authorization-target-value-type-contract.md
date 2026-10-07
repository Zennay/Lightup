# Scope authorization: non-string Target value contract

Tracking issue: #494.

## Boundary

`Target.value` is an authorization identity input. Runtime type annotations do not prevent callers from constructing `Target` with non-string values, so the scope boundary itself must fail closed before host normalization.

This acceptance child is intentionally tests/docs-only. It does not modify the active `scope.py`, model, activation, execution-policy, domain/state, webapp, or target-capable source owners.

## Required behavior

For every non-string `Target.value`:

- the decision is denied;
- `normalized_host` is `None`;
- the reason is exactly `ScopeReason.INVALID_TARGET`;
- no implicit string conversion creates a host identity;
- no parser/type exception escapes the scope boundary.

The regression matrix covers `None`, booleans, integers, bytes, bytearray, tuple and dict values. This intentionally spans values that fail before normalization as well as bytes-like values that can make it past `.strip()` and fail later during URL parsing.

Canonical string behavior stays unchanged: blank input remains invalid, loopback remains loopback, private lab addresses retain their existing policy path, and unknown public addresses remain out of scope.

## Expected current result

On parent commit `1abc16a66fc490b1ba7272890dfbf498482fca9c`, the non-string cases are expected RED:

- values without `.strip()` leak `AttributeError`;
- bytes-like values can leak `TypeError` when string URL operations are applied;
- canonical string controls remain green.

A future source owner can satisfy this contract by rejecting non-string identity input before normalization. This child does not prescribe or implement the source fix.

## Safety

Offline/in-memory authorization-input validation only. No DNS, network requests, target interaction, scanning, execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
