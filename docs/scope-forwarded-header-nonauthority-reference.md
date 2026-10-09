# Forwarded transport metadata is not authorization

## Scope
This isolated **offline reference** documents a trust boundary for HTTP `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and similarly named proxy metadata.

Proxy metadata describes a claimed transport path; it must not issue, renew, revoke, transfer, or widen consent. Do not use it to choose a different tenant, request, asset, capability, revision, approval, or security mode.

## Synthetic regression contract
`tests/test_scope_forwarded_header_nonauthority_reference.py` exercises:
- matching reference identity as necessary-only conditional control;
- inactive or unverified grants and spoofed trusted host/user;
- tenant/request/asset/capability mismatches;
- stale revision and strict int typing on both grant and dispatch;
- matching invalid control-character, non-ASCII, empty, and overlong identities across all four binding fields;
- forged grant envelopes;
- hostile header objects that must never be inspected, and polymorphic metadata types;\n- exact booleans for issuer verification and active state;
- header mutation that cannot affect the authorization outcome.

The predicate deliberately ignores proxy headers. Its `verified=True` fixture is **not** issuer signature verification; a positive result is **not** authority to execute any tool. Production code must separately validate authenticated provenance, operator approval, bounded scope, risk and current revocation state at the final dispatch gate.

## Safe validation and promotion
```sh
python -m unittest discover -s tests -p 'test_scope_forwarded_header_nonauthority_reference.py' -v
```

Require green checks on the **exact PR head**, hosted Python 3.11 and 3.14 and canonical permanent VPS CI, followed by review from the production scope/executor owner. Until then leave the PR in **draft**. No active targets, DNS, network, scanning, grant activation, handler dispatch or deployment belong to this change.
