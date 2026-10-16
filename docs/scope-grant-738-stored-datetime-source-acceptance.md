# #738 — exact built-in datetime for stored AuthorizationGrant bounds

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**.
Only additive offline acceptance over source-owner PR #100, SHA
`ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`.
No `src/lightup/engagements.py` edits or product authorization fixes here.

## Actual gap

`AuthorizationGrant.is_current(now)` evaluates
`self.valid_from <= now <= self.valid_until` using rich comparisons supplied
by grant-held objects. An injected `datetime` subclass can override
`__le__` for a future start or `__ge__` for an expired end and claim the
window is current. Annotation `datetime` is not an exact runtime type gate.
This issue concerns **stored window values**, not a polymorphic evaluation
`now` (#734) or the durable issuance path (#647).

## Acceptance for PR #100 source owner

- Reject both stored boundaries unless `type(boundary) is datetime` and
  each boundary is timezone-aware, before any user-defined comparison executes.
  Source-owner repair must produce controlled `ValueError` on malformed data.
- Exact built-in aware future-start and expired-end windows return `False`.
  Current canonical windows and exact inclusive endpoints preserve behavior.
- Revoked grants still deny; no caller-owned grant/boundary mutation or
  coercion, no target-capable execution.
- Convert seven `expectedFailure` stored-subclass tests to ordinary passing
  negatives after source-owner repair. The eight positive controls must
  remain ordinary PASS.

## Offline acceptance

```sh
PYTHONPATH=src python -m unittest discover -s tests \
  -p 'test_scope_grant*_738.py' -v
```

The additional `tests/test_scope_grant_precomparison_738.py` enforces rejection **before invoking any foreign `__le__`/`__ge__`** method, including a throwing override. The synthetic untrusted subclasses deliberately override separate comparison
directions. There is no network, durable SQLite, grant issuance, secrets,
consent material, scanner, handler, or target action. The isolated hosted
3.11/3.14 workflow is diagnostic only; `expectedFailure` means **still
vulnerable until product source is repaired**, even if CI reports SUCCESS.

PR #100 retains sole production ownership. Independently authenticated
client/operator consent, at-use revocation, independent security/privacy,
whole-project exact-head hosted and genuinely registered permanent
`vps-bb300bba` CI green, source-owner review and explicit HUMAN GO remain
mandatory. Keep all work DRAFT/HOLD; no merge, deploy, scan, dispatch, grant or
release from this acceptance artifact.
