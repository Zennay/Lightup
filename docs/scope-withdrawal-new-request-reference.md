# Withdrawal versus a newly created request — offline reference

## Invariant

Changing a request identifier **cannot** re-enable a withdrawn consent grant.
An issuer-owned consent epoch must bind tenant, asset and the request snapshot.
A fresh request after withdrawal is eligible for consideration only with a
**new explicit issuer-approved consent** carrying the new epoch; issuance is
not inferred from the request's existence or its new identifier.

The pure reference predicate in
`tests/test_scope_withdrawal_new_request_reference.py` tests matching
identity and epoch, inactive consent, stale requests after reissuance,
cross-tenant/asset switches, malformed epochs, truthy flags, hostile IDs,
subclass injection and input purity.

## Production integration required (owner: PR #107)

1. Persist consent epochs in a trusted authorization record, independently
   from user-supplied requests. Epochs must advance on withdrawal/reissue and
   must not be reset by deletion/recreation or backup restoration.
2. Check the latest issuer-owned status, tenant, asset, consent epoch, risk,
   grant revision, expiry and operator approval at dispatch, retries and
   asynchronous resumed steps; a request identifier alone never authorizes.
3. Withdrawal cancels queued jobs and prevents stale in-flight requests from
   reaching any handler or network I/O. Re-approval must create a new grant;
   it must never reactivate an old snapshot.
4. Avoid a check/use race: enforce issuance, withdrawal and dispatch through
   transactionally consistent state/fencing as appropriate.
5. Prove denial with zero handler invocations and zero target I/O on the exact
   release head, including permanent VPS runner evidence.

## Limitations and collision boundary

This module is a **synthetic, conditionally eligible reference**. Its dataclasses
do not authenticate an issuer, persist revocations or grant execution access.
The positive example must never be interpreted as production authority.
Source owner #107 owns executor integration; parallel consent withdrawal,
rollback, approval and dispatch PRs are not modified.

Run offline: `python -m unittest discover -s tests -p 'test_scope_withdrawal_new_request_reference.py' -v`.

No DNS, sockets, public targets, scanners, capability execution, deployments,
grant activation or widening of authorization.
