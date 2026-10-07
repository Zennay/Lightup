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

Canonical exact `Target` objects retain existing loopback, private-lab and public out-of-scope behavior.

## Expected current result

On exact parent `1abc16a66fc490b1ba7272890dfbf498482fca9c`:

- `None`, strings and dictionaries can leak `AttributeError`;
- a duck-typed object exposing `value="127.0.0.1"` is accepted as loopback despite not being a `Target`;
- a `Target` subclass whose stored dataclass value is `8.8.8.8` can override attribute access so the policy evaluates `127.0.0.1` and allows loopback;
- a second `Target` subclass can store `authorization=None` yet override authorization access to return a fresh current `Authorization`, allowing an explicit public host without the authorization stored on the target;
- exact `Target` controls remain green.

The future source repair belongs to the active scope source owner. This acceptance child does not edit production code.

## Safety

Offline/in-memory authorization-input validation only. No DNS, network I/O, target interaction, scanning, execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
