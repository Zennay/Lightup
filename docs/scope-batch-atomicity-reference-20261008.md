# Scope authorization: offline batch atomicity reference

Phase M7/ST5; reference-only, not production integration.

## Risk
A batch with one eligible and one unauthorized item must not be partially dispatched. A loop that authorizes and executes sequentially violates fail-closed semantics.

## Integration contract for source owner (#107)
1. Validate the entire immutable batch before invoking any handler.
2. Require canonical exact identity and container types, with no implicit coercion.
3. Bind every item to its tenant, engagement, asset, capability and risk scope.
4. Revalidate live grants, expiry and revocation at execution time.
5. Address revocation races via reviewed atomic dispatch or lease semantics.
6. On any denial invoke zero handlers, without sensitive diagnostics.
7. If partial execution is ever supported, require an explicit separate API and reviewed semantics.

## Offline regression
Run: python -m unittest discover -s tests -p test_scope_batch_atomicity_reference_20261008.py -v
Eight synthetic tests cover canonical eligibility, out-of-scope assets in either order, cross-tenant and engagement items, capability and risk escalation, empty/mutable containers, malformed identities and inactive grants, plus non-mutation.

## Release gate
This reference does not prove executor enforcement. Require source-integrated zero-handler-invocation tests, concurrent revocation coverage, exact-head hosted and permanent VPS CI evidence and independent owner review.
No real targets, DNS/network access, scans, activation, dispatch or deployment are authorized.