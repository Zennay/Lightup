# LightUp #738 — direct-grant datetime identity acceptance (offline)

## Purpose, original source ownership and posture

[Issue #738](https://github.com/Zennay/Lightup/issues/738) requires
`AuthorizationGrant.is_current()` to **fail closed** for subclassed
`datetime` validity fields that can override comparisons to make future or
expired authorization look current.

**Production repair belongs to the existing [#100 source owner](https://github.com/Zennay/Lightup/pull/100)**.
This independent draft branch adds no installed enforcement, active target
functionality, dispatcher changes, persistence, CI workflow or runner edits.

## Deliverable A — independent expected-RED acceptance

`tests/test_scope_direct_grant_datetime_identity_red_20261014.py`
exercises real `AuthorizationGrant` + pure `ExecutionPolicy` with synthetic
fixed UTC values. It includes ordinary positive and expired/future controls,
inclusive boundaries and **five deliberately expected RED** comparator-spoof
scenarios (direct and policy). The separate
`tests/test_scope_direct_grant_red_witness_integrity_20261014.py`
runs all five expected failures under isolated `unittest.TestResult`,
refuses hidden runtime exceptions and XPASS, and proves these are actual
assertion witnesses. No target I/O, sockets, DNS or client DB.

These five expected failures are **unresolved real-source safety requirements**,
not proof of enforcement. After source-owner repair, remove
`@unittest.expectedFailure` and demand ordinary PASS.

## Deliverable B — working opt-in canonical window-shape diagnostic

`src/lightup/direct_grant_window_shape_review_738.py` adds an ordinary,
directly usable in-process
`review_direct_grant_window_shape(grant, observed_at=...)`.

- Accepts only the **exact built-in** `AuthorizationGrant` object, exact
  `datetime` values (not subtypes) and **exact built-in fixed-offset**
  `datetime.timezone` objects (UTC and stable nonzero offsets). Custom
  `tzinfo` implementations are conservatively refused without calling their
  methods.
- Refuses malformed/non-aware/omitted time, reversed/empty windows and
  evaluation instants outside the half-open? **No:** follows legacy issue
  #295's **inclusive** `valid_from <= observed_at <= valid_until` boundary,
  including the exact expiry instant.
- Never falls back to a wall clock. Caller must explicitly provide a trusted
  time if they need more than local shape checking.
- Returns only `WindowShapeReview(decision, reason)`: `HOLD` or
  `REVIEW_ONLY`. All five authority markers are read-only computed
  hard-false properties and are fixed false in the privacy-safe `as_receipt`
  dictionary. No grant ID, target, tenant, asset or private data is emitted.
- This checks **only the declared temporal shape**. It cannot establish that
  an authorization grant was issued by a trusted human, actually persisted,
  belongs to a tenant or current request, remains unrevoked, covers an asset,
  has a permitted capability, or implies an authorized execution.
- Does not integrate into `ToolExecutor`, grant issuance, web APIs, persistent
  data or active networking. `REVIEW_ONLY` deliberately does not represent a
  successful authorization, an execution permit, merge/release permission or
  self-hosted CI attestation.

Usage (offline synthetic only):

```python
from datetime import datetime, timedelta, timezone
from lightup.direct_grant_window_shape_review_738 import review_direct_grant_window_shape
from lightup.engagements import AuthorizationGrant, ScopeDefinition, RiskLevel

now = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)
grant = AuthorizationGrant(
    "fictional", "tenant.test", "engagement.test", "operator.test", "NOT_CONSENT",
    ScopeDefinition(("fixture.example.test",), RiskLevel.LOW_IMPACT,
                    allowed_capabilities=("web-baseline",)),
    now - timedelta(minutes=1), now + timedelta(minutes=1),
)
receipt = review_direct_grant_window_shape(grant, observed_at=now).as_receipt()
assert receipt["decision"] == "REVIEW_ONLY"
assert not receipt["authorization_verified"]
```

## Test execution

```bash
python -m unittest discover -s tests -p 'test_scope_direct_grant*738*.py' -v
```

The opt-in functionality has its own **ordinary PASS** tests in
`tests/test_scope_direct_grant_window_shape_review_738.py` covering
malformed/subclass types, UTC and offsets, custom exploding timezone, time
bounds, privacy, input purity, zero authority and forbidden network/database.

## Independent release prerequisites

1. #100 original source owner **must** enforce exact built-in aware datetime
   validity fields at the actual production decision boundary.
2. Convert the five **expected RED** original-source assertions into
   ordinary PASS and independently review both real code and test witness
   quality. This standalone diagnostic does *not* fulfill step 1.
3. Compose against then-current main without overlapping other workers,
   verify final SHA both GitHub-hosted Python interpreters + genuine producer
   integration and **registered permanent VPS-runner execution**.
4. Confirm trusted customer consent and current revocation, tenant, asset,
   risk and capability gates, privacy/security review and applicable
   activation/release decision before any real-target work.

**INCUBATE M3/M7, PLAN/LAB ONLY. No real scans, deployment, permit, direct
authorization, or merge claim is created by this packet.** Entire branch
touches only its newly added owned paths.
