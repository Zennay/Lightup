# #737 opt-in offline revocation provenance review — non-authorizing

LightUp stage: **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**.

## The boundary

This is a **standalone, opt-in, pure in-memory review module**. It is intentionally located at `scripts/scope_737_revocation_metadata_review.py` rather than being wired into any installed scope, active executor, persistent store, WSGI, worker, authorization grant, or scanning endpoint. **Never use it as an authorization decision.** Every output sets `decision=HOLD`, `can_authorize=False`, `can_dispatch=False`, `can_release=False`.

The selected source-owner [PR #100](https://github.com/Zennay/Lightup/pull/100) retains all rights to implement the actual production fix to [#737](https://github.com/Zennay/Lightup/issues/737). This separate script does not change that source or confer consent to real targets.

## Data rules

The review takes only `revoked_at`, `revoked_by`, and `revocation_reason`, with **keyword-only** arguments. It does not read grant identity, tenant, asset, scope, risk, operator account, endpoint, secrets, browser cookies, or evidence payloads.

- All three `None` fields: `no_revocation_claim`. Still `HOLD`; other checks and proof remain missing.
- Time present, exact aware built-in `datetime`, and both actor/reason exact bounded trimmed built-in text: `revocation_recorded`. Still `HOLD` and require independent trusted revocation verification.
- Missing time with actor or reason: `inconsistent` / `stale_revocation_provenance`.
- Time without required actor/reason: `inconsistent` / `incomplete_revocation_event`.
- Noncanonical text, subclassed/spoofing objects, oversized (>256) or blank/padded values, noncanonical or naive timestamps: `inconsistent` / specific bounded reason codes.
- The output is frozen, does not reflect raw actor/reason strings or host/tenant identity, and does not invoke untrusted input `__bool__` / `__str__` / `__eq__` / `strip`.

This is only a **review preview**, not a complete source grant coherence or current grant check. It is intentionally stricter about completeness of revocation metadata than the current installed source. This cannot substitute for real source-owner repair, live persisted source of truth, or operator/customer authorization.

## Real proof plan

```sh
python -m unittest discover -s tests -p 'test_scope_737_offline_revocation_metadata_review_20261015.py' -v
```

The 22 additional tests include explicit authorizing-flag tripwires, unchanged input, spoofing and type confusion, 80+ adversarial combinations, privacy-safe result rendering, and source/current independent acceptance. Use original exact-SHA GitHub logs and both Python 3.11/3.14 plus producer integrations; verify permanent registered VPS separately, not by queued labels.

## Owner handoff and release gate

Original [#737 source RED and direct installed-policy tests](../tests/test_scope_737_stale_durable_revocation_provenance_20261015.py) and [non-installed patch preview](../tests/test_scope_737_revocation_reference_preview_20261015.py) remain separate. They prove the original problem and a narrow-only desired behavior. The new reviewer is additive, not integrated.

Fix may only be shipped by the relevant owner after genuine source changes, all expected RED converted to ordinary PASS and unsafe diagnostic witness retired, independently verified tenant/grant lifecycle, persisted revocation and FK provenance, current-grant atomic dispatch, network isolation, security/privacy review, self-hosted permanent VPS proof, and explicit human release.

**NO MERGE · NO DEPLOY · NO GRANTS · NO LIVE TARGETS · NO SCANS · NO GO.**
