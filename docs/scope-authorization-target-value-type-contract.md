# Scope authorization: non-string Target value contract

Tracking issue: #494.

## Boundary

`Target.value` is an authorization identity input. Runtime type annotations do not prevent callers from constructing `Target` with non-string values, so the scope boundary itself must fail closed before host normalization.

This boundary requires an **exact built-in string**, not merely `isinstance(value, str)`. A `str` subclass can override methods such as `.strip()`; if accepted, a caller can make the visible value differ from the host identity that the policy actually evaluates.

This acceptance child is intentionally tests/docs-only. It does not modify the active `scope.py`, model, activation, execution-policy, domain/state, webapp, or target-capable source owners.

## Required behavior

For every non-exact-string `Target.value`:

- the decision is denied;
- `normalized_host` is `None`;
- the reason is exactly `ScopeReason.INVALID_TARGET`;
- no implicit string conversion creates a host identity;
- no overridden string method can substitute a different host identity;
- no parser/type exception escapes the scope boundary.

The regression matrix covers `None`, booleans, integers, bytes, bytearray, tuple and dict values, plus a malicious `str` subclass whose `.strip()` returns loopback while the stored text is a public IP.

Canonical built-in string behavior stays unchanged: blank input remains invalid, loopback remains loopback, an explicitly enabled private-lab policy still classifies an ordinary private address as private lab, and an unknown public address remains out of scope. The control intentionally does not pin the default value of `allow_private_lab`; #103/#100 own that policy default and special-address narrowing.

## Expected current result

On parent commit `1abc16a66fc490b1ba7272890dfbf498482fca9c`, the acceptance is expected RED:

- values without `.strip()` leak `AttributeError`;
- bytes-like values can leak `TypeError` when string URL operations are applied;
- the crafted string subclass can turn visible `8.8.8.8` into evaluated `127.0.0.1`, producing an allowed loopback decision;
- canonical built-in string controls remain green.

The same target-input gaps are still present on active source-owner PR #100 head `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`; the explicit private-lab control is written to remain compatible with #100's intentional default-deny private-lab policy.

A future source owner can satisfy this contract by rejecting non-exact-string identity input before normalization. This child does not prescribe or implement the source fix.

## Safety

Offline/in-memory authorization-input validation only. No DNS, network requests, target interaction, scanning, execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
