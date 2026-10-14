# Scope authorization: no implicit delegation (offline review contract)

Status: **M7/ST5 review contract — not an authorization grant**. This document
does not enable production admission or real-target execution.

## Security boundary

Three distinct questions must be answered affirmatively, in order, before
any target-capable work is eligible:

1. **Membership:** Is the canonical target inside the exact explicitly
   declared host/IP/CIDR scope? An authorization record must never create,
   infer, expand, or repair target membership.
2. **Authority:** Is there explicit, current, non-revoked permission from the
   appropriate asset owner for **this exact asset and requested operation**?
   A tenant login, client association, discovery signal, paid subscription,
   risk selection, previously issued report, or successful simulation is not
   permission.
3. **Activation:** Is the requested capability explicitly enabled for the
   authorized engagement and its declared risk limits? An approved engagement
   alone must not activate an otherwise disabled capability or adapter.

Every check must fail closed independently. There must be no fallback from
an unknown, expired, unparseable, ambiguous, or mismatched authorization to
a broader permission class.

## Delegation and evidence

- Evidence of asset ownership or client representation is **not** itself a
  permission to run a test; document who granted permission, what was granted,
  the exact canonical assets/operations, and its effective/revocation window.
- A person with access to a tenant may submit an assessment *request* but
  must not implicitly grant authorization on behalf of an asset owner.
- Changes to owner, assets, operation, risk ceiling, or time bounds require
  a new explicit approval; never mutate an approved grant to widen it.
- Discovery and Security Twin predictions are never a source of live
  authorization.
- Keep a denied outcome and an audit-safe reason code; exclude credentials,
  authorization tokens, and sensitive target details from untrusted diagnostics.

## Review matrix (no live targets)

| Scenario | Expected result |
| --- | --- |
| Valid request, unknown public host | DENY: out of declared scope |
| Valid request, external IP outside all CIDRs | DENY: out of declared scope |
| Target in scope, expired or revoked permission | DENY: authority invalid |
| Target in scope, permission for a different asset | DENY: asset mismatch |
| Target in scope, permission for another operation | DENY: operation mismatch |
| Target and authority valid, capability disabled | DENY: activation disabled |
| Passive public discovery without explicit active grant | PASSIVE ONLY; no target-capable escalation |
| Simulation predicts a vulnerability | NO live authorization side effect |
| Requested risk exceeds approved ceiling | DENY: exceeds approval |
| Explicitly authorized in-scope operation with activation | Eligible for the normal execution-policy gates; **not** an unconditional allow |

## Integration constraints

This is an independent reviewer reference, **not proof that production code
implements these checks**. The production admission owner must map each row
to executable offline regressions and confirm that every executor/adapter
shares the same canonical checks. Do not use this document as a substitute
for signed authorization records, human approval, CI evidence, or release
gates. No scanning, DNS lookups, HTTP requests, exploitation, or other
target interaction is required or authorized by these review cases.
