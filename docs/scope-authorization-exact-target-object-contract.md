# Scope authorization: exact Target object contract

Tracking issue: #496.

## Boundary

`ScopePolicy.decide()` is an authorization decision boundary. Python annotations do not enforce that the argument is actually a `Target`, and subclassing can override attribute access after an apparently canonical dataclass construction.

This contract is separate from #494. #494 owns the type of `Target.value` **inside an exact Target**. This contract owns the type identity of the object passed to `decide()`.

## Required behavior

Only `type(target) is Target` may enter target normalization and authorization evaluation.

All other objects, including `None`, strings, dictionaries, duck-typed objects and `Target` subclasses, must return:

- `allowed=False`;
- `normalized_host=None`;
- `reason=ScopeReason.INVALID_TARGET`.

No exception may escape. Duck typing must not create scope authority. A subclass must not be able to replace either the dataclass's stored target identity or its stored authorization with a different value through overridden attribute access.

Canonical exact `Target` behavior stays intact: loopback remains loopback, an explicitly enabled private-lab policy still classifies an ordinary private address as private lab, and an unknown public address remains out of scope. The control intentionally does not pin the default value of `allow_private_lab`; #103/#100 own that policy default and special-address narrowing.

## Expected current result

On exact parent `1abc16a66fc490b1ba7272890dfbf498482fca9c`:

- `None`, strings and dictionaries can leak `AttributeError`;
- a duck-typed object exposing `value="127.0.0.1"` is accepted as loopback despite not being a `Target`;
- a `Target` subclass whose stored dataclass value is `8.8.8.8` can override attribute access so the policy evaluates `127.0.0.1` and allows loopback;
- a second `Target` subclass can store `authorization=None` yet override authorization access to return a fresh canonical `Authorization`, allowing an explicit public host without the authorization stored on the target;
- exact `Target` controls remain green.

The authorization-spoof fixture stays inside #496's outer-object boundary: it always returns a real `Authorization`, not a duck-typed authorization object. When the source-owner schema exposes an `assets` field (as #100 does), the fixture populates the matching explicit host so the proof remains about the `Target` subclass replacing stored state rather than about #302's authorization-object typing or #100's asset binding.

These exact Target-object gaps are still present on active source-owner PR #100 head `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`. The controls use explicit private-lab opt-in so they compose with #100's intentional default-deny change rather than competing with it.

The future source repair belongs to the active scope source owner. This acceptance child does not edit production code.

## Safety

Offline/in-memory authorization-input validation only. No DNS, network I/O, target interaction, scanning, execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
