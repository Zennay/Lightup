# Credential fingerprints do not authorize scope

This is an **offline reference only**, not an implementation of authentication, scope grants, credential verification, or execution permission.

## Trust boundary

A credential fingerprint, API-key hint, token prefix, hash string, log label, or UI-visible identifier supplied with a request is metadata and **cannot** issue or revive consent, bridge tenants, override a request/revision/capability mismatch, or resurrect a revoked grant. Its textual equality with an alleged trusted value does not prove possession, cryptographic validity, signature verification, issuer provenance, or liveness.

`tests/test_scope_credential_fingerprint_nonauthority_reference.py` models the necessary identity/active comparisons separately from an untrusted fingerprint. A positive result means **only conditional consistency**; actual access must remain denied without independently verified session principal, issuer-owned current grant, explicit authorized target, approval provenance, revocation/epoch and risk checks, and atomic revalidation before dispatch.

## Integration acceptance (production owner, not implemented here)

1. Bind authenticated principal and current issuer grant through trusted components, never through fingerprint text or a caller/model-provided boolean.
2. Deny malformed typed identifiers, stale versions, revocation, tenant/request/capability mismatch before queue admission and again at dispatch.
3. No cached positive fingerprint, UI status, report, or scan output can mint permission or survive withdrawal.
4. Prove denial with zero handler invocations, DNS, socket, target traffic or other side effects.
5. Pin integration results to the exact candidate head with hosted Python 3.11/3.14 and canonical permanent VPS runner checks; obtain owner review before promotion.

## Isolation and local test

Only this document and its stdlib unittest module are added. No existing production source, executor, approval workflow or active parallel PR paths are modified. No credentials or real target interactions.

```sh
python -m unittest discover -s tests -p 'test_scope_credential_fingerprint_nonauthority_reference.py' -v
```

The synthetic grant is **not** cryptographically trusted. This test is not evidence of live enforcement.
