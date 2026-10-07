# Risk decision approval identity contract

Issue: #791  
Source owner: draft PR #146 (`decide_risk_elevation`)  
Pinned source head: `33c67f8e8b17bd9214c29d02fc52954cc42655da`

## Boundary

A risk-elevation decision is authorization-significant. The approval row that is
validated for pending state, destructive-risk policy and self-approval must be
the same approval row that is mutated and returned.

The caller-supplied `approval_id` therefore cannot remain a reusable
annotation-only SQLite parameter. It must be accepted only as one exact,
non-blank built-in string identity before any database bind occurs.

## Regression

`tests/test_scope_authorization_risk_decision_approval_identity.py` constructs
an object implementing SQLite's adaptation protocol. Its first bind resolves to
a request made by a different actor, while later binds resolve to a request made
by the reviewer themselves.

On the pinned #146 source, the first row can pass the self-approval check and a
later bind can target the reviewer's own row. The desired behavior is to reject
the non-canonical identity before SQLite calls its adapter, leaving both rows
PENDING and all decision audit fields empty.

The companion green control preserves canonical exact-string behavior:
self-approval is denied and an unrelated operator can still approve once.

## Ownership and safety

This sidecar adds tests and documentation only. PR #146 retains production
ownership of the serialized risk-decision implementation. #657 separately owns
decision-actor identity; #656 owns risk-justification intake.

No target interaction, DNS/network I/O, scanning, capability execution,
remediation/retest execution, deployment, verdict creation or attack-path
mutation is introduced.
