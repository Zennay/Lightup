# Scope authorization: ambiguous evidence JSON (offline reference)

Status: **proposed acceptance contract only**; no production grant issuer or authorization gate has been changed. Current phase: M7/ST5 fail-closed hardening.

## Boundary

An externally supplied authorization-evidence envelope must never acquire authority through permissive JSON parsing. The standalone Python unittest reference deliberately rejects duplicate object keys at every nesting depth, JavaScript-style non-finite numbers, non-boolean approval values, boolean-as-integer revision, unknown fields, oversized envelope data, and malformed structural types. The positive fixture proves parsing **only**, not permission.

The reference schema (`grant_id`, `revision`, `evidence: {issuer, approved}`) is intentionally illustrative and **is not** the application's canonical grant schema. Its positive case cannot issue consent, establish human approval, authorize execution, bind tenant/target/scope/risk, bypass expiration or supersede a revoked grant.

## Production-owner acceptance before integration

- The owning authorization implementation (PR #107 and its follow-ups) must choose its actual persisted/wire schema and canonical parsing boundary; do not blindly adopt this reference's field names.
- Reject duplicate JSON keys recursively **before** ordinary last-value-wins decoding can silently override a grant revision, human approval, issuer, tenant, allowed asset, capability or risk bound.
- Reject NaN/Infinity/-Infinity, bool-as-int, and non-exact booleans in semantically typed fields.
- Bind parsed material to trusted issuer lineage and latest live state; no caller-supplied `approved: true` may count as human consent.
- Revalidate consent, tenant isolation, scope, capability, risk, expiry, revocation and authorization revision at admission and dispatch. Audit denial without leaking evidence secrets.
- Keep active real-target execution disabled pending exact-head hosted + permanent VPS CI, owner review and documented activation approval.

## Offline command

```sh
python -m unittest discover -s tests -p 'test_scope_authorization_evidence_json_ambiguity_reference.py' -v
```

The reference uses only Python stdlib; no DNS, sockets, target contact, scanners, model invocation, capability execution or deployment. It must remain separate from the numerous open scope-authorization PR branches and from PR #107's production source files.
