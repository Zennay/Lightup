# Scope authorization callback isolation (offline acceptance)

## Invariant

An authorization object is not a source of target scope membership. When a
target cannot be normalized or is outside all explicit host/network membership
rules, `ScopePolicy.decide` must reject it **before** consulting any methods
on an attached authorization object. This also holds when
`require_authorization_for_public=False`.

## Coverage

`tests/test_scope_authorization_callback_isolation.py` covers an undeclared
public hostname, an address outside the declared public network, a blank
target and disabled public authorization requirement. Two additional control
cases ensure loopback and private-lab decisions remain independent of the
public authorization callback, preserving their existing classification. Additional\nnegative cases exercise private-lab disabled and an undeclared IPv6 CIDR,\nso an attached authorization cannot rescue either rejected target. An adversarial
authorization object raises from its `is_current`, `is_revoked` and
`allows_asset` hooks to detect inappropriate invocation. Expected outcomes:
`OUT_OF_SCOPE` and `INVALID_TARGET`, with no callbacks executed.

This is a **test-only** guarantee and does not assert that a member target is
authorized, or define the positive grant protocol. Existing production owners
retain exclusive control of authorization/grant implementation.

Run offline with:
`PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_authorization_callback_isolation.py' -v`

No network, DNS, scanning, target interaction, or execution is required.
