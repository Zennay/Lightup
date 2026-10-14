# Scope change / approval snapshot reference (offline)

This isolated test-only reference contract models **approval invalidation after
any material change** in the engagement's declared targets, allowed capabilities,
risk level or engagement identity. It does **not** authorize a target and does
not integrate with production gates. Real-target activation remains disabled.

## Contract

1. Capture a canonical, strictly typed snapshot of the explicitly approved
   engagement, targets, capabilities and risk level.
2. Record the lowercase SHA-256 fingerprint with approval evidence, actor,
   issuance and expiry timestamps in the future production workflow.
3. Compare the fingerprint against the full current declaration immediately
   before any execution decision. Any mismatch requires fresh human approval;
   malformed data and missing evidence deny.
4. Reordering distinct targets/capabilities alone is not an authority change;
   adding, removing or replacing a member always is.
5. The fingerprint **is not** an approval signature, proof of authorization,
   identity verification, a cryptographic attestation of an approver, or a
   substitute for authorization time windows, revocation and per-target gates.
6. Production integration must ensure scope and approval are read atomically,
   verify approver and tenant binding, prevent replay, and recheck revocation at
   dispatch. A TOCTOU-safe persisted transaction is not established by this test.

## Offline verification

`python -m unittest discover -s tests -p 'test_scope_change_approval_fingerprint_reference.py' -v`

Tests make no DNS, HTTP, socket, persistence, scan, or real-target calls.
This reference deliberately lives in tests and must not be imported into a
production authorization path. The integration owner should translate the
contract into the actual trusted approval/dispatch boundary after coordinating
with existing scope-authorization work.
