# Scope authorization — issuer key rotation offline reference

This PR adds an isolated, pure Python stdlib **reference model**, not enforcement. It complements the independent key-rotation acceptance matrix in PR #1040 and does not change that PR or production executor owner PR #107.

## Fail-closed invariants

- A key must be issuer-owned, currently active, identified by exact issuer/tenant/key ID and generation, with one explicitly pinned algorithm.
- Retired keys, stale generations, future/mismatched generations, issuer/tenant confusion, algorithm substitution and revision mismatches must deny.
- Malformed types, truthy-but-not-boolean flags, subclassed/forged envelopes and ambiguous identity strings must deny.
- Key-rotation floor is independently trusted and monotonically maintained. It cannot originate from the request or claim.
- **Necessary not sufficient**: matching synthetic fields never prove signatures, key custody, operator consent, current revocation, protected trust-store authenticity, or grant validity.

## Production owner contract

PR #107 must bind issuer-verified signed grants to an independently stored trust anchor, authenticated session/operator approval, current authorization revision, current revocation and *fresh* floor before each queued, retried or immediate dispatch. Key rotation must atomically retire prior signing authority. No fallback to unknown/retired keys or unrecognized algorithms, and never infer permission from these test fixtures.

## Isolation and review gate

Only this new documentation file and `tests/test_scope_issuer_key_rotation_reference.py` are owned by this PR. No external targets, DNS, sockets, signing secrets, scans, active capabilities, grant issuance, deployment, or production changes.

Run offline: `python -m unittest discover -s tests -p 'test_scope_issuer_key_rotation_reference.py' -v`.

Keep draft until exact-head hosted Python 3.11 + 3.14 and canonical permanent VPS CI evidence, followed by production owner review. Passing reference tests is **not** proof of enforceable authorization or permission to activate real-target assessment.
