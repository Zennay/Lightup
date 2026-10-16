# Risk decision approval identity contract

Issue: #791  
Source owner: draft PR #146 (`decide_risk_elevation`)  
Pinned source head: `33c67f8e8b17bd9214c29d02fc52954cc42655da`

## Boundary

A risk-elevation decision is authorization-significant. The approval row that is
validated for pending state, destructive-risk policy and self-approval must be
the same approval row that is mutated and returned.

The caller-supplied `approval_id` therefore cannot remain a reusable
annotation-only SQLite parameter. It must be accepted only as an exact built-in
string with non-blank canonical content before any database bind occurs.
String subclasses, adapter objects, blank strings and whitespace-only strings
are invalid decision identities.

## Regression

`tests/test_scope_authorization_risk_decision_approval_identity.py` covers four
parts of the contract.

- A SQLite-adaptable object exposes approval A for the safety read and approval B
  for later binds. The authority-shaped case makes B a request created by the
  reviewer themselves.
- An equal-content `str` subclass is rejected rather than treated as a
  canonical decision identity.
- Blank and whitespace-only exact strings are rejected as malformed input.
- Canonical exact-string behavior remains intact: self-approval is denied and
  an unrelated operator can still approve once.

On the pinned #146 source, the stateful adapter can make the first row pass the
self-approval check and a later bind target the reviewer's own row. The desired
behavior is rejection before SQLite calls the adapter, leaving every involved
row PENDING and all decision audit fields empty.

## Ownership and safety

This sidecar adds tests and documentation only. PR #146 retains production
ownership of the serialized risk-decision implementation. #657 separately owns
decision-actor identity; #656 owns risk-justification intake.

No target interaction, DNS/network I/O, scanning, capability execution,
remediation/retest execution, deployment, verdict creation or attack-path
mutation is introduced.
