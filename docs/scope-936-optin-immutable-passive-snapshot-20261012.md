# W11 — isolated immutable passive-prospect snapshot (opt-in implementation)

Scope: [#936](https://github.com/Zennay/Lightup/issues/936), continuing W10 [DRAFT PR #1245](https://github.com/Zennay/Lightup/pull/1245) without touching its branch or the active source owner [PR #175](https://github.com/Zennay/Lightup/pull/175).

## Implemented (new files only)

- `src/lightup/passive_snapshot.py`: standalone opt-in value model `PassiveProspectSnapshot`, canonical immutable `AdmittedPublicSignal` tuples, fail-closed `from_signals(...)` batch construction and `with_signal(...)` copy-on-write admission.
- `tests/test_scope_passive_immutable_snapshot_20261012.py`: 20 synthetic unit methods for constructor/batch/append guards, immutable identity/collection, public-source and interaction constraints, exact primitive/schema metadata, NaN/infinity denial, bad record type, caller alias integrity, late invalid item atomic failure, and explicit size limits.

Unlike v9/v10's intentionally RED tests of the legacy mutable `ProspectProfile`, W11 supplies working executable *opt-in reference* behavior on a **fresh canonical main base**. The legacy `ProspectProfile` remains unchanged and ungated.

### Exact behavior

1. Only exact built-in `str` nonblank identity, organization, source and summary strings up to 4096 characters are admitted, without trimming/coercion.
2. Every admitted signal is an exact `ProspectSignal` with canonical `SignalCategory`, exact finite built-in `float` confidence in [0,1], exact `bool` flags, `public_source=True`, and `requires_target_interaction=False`.
3. Incoming `ProspectSignal` data is copied into a `NamedTuple` of immutable primitive fields. Changes to caller-owned source objects after admission do not change previously made snapshots.
4. A snapshot holds an exact immutable tuple of up to 256 canonical records. Constructor pre-seeding with lists, arbitrary records or otherwise malformed records fails before returning state.
5. `with_signal` makes a fresh snapshot. Rejection leaves the original existing snapshot untouched. It neither mutates a legacy `ProspectProfile` nor persists any client state.
6. Text and signal-count limits are conservative **local opt-in budgets**, not decisions on client scope or permission.

### Evidence / reproduction

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_passive_immutable_snapshot_20261012.py' -v
```

GitHub-hosted full-suite Python 3.11/3.14 and genuine producer integrations, plus **separate registered permanent VPS CI**, must be inspected at the *exact final commit SHA*. Green reference tests **do not** prove installed runtime enforcement.

### Collision / release policy

- Separate branch on `main`; do not edit `src/lightup/discovery.py`, #175, existing v8/v9/v10, other workers' source/tests, webapp, target discovery, scanner, domain authorization, grant issuance or deployment.
- No DNS, socket, public-target probing, active check, authorization grant, user role change, real customer data or external task dispatch.
- The reference **does not issue authorization**, certify third-party prospects, or validate ownership of assets. It is not wired into real prospecting paths; #175 must evaluate integration and independent security/privacy/source review.
- Python's frozen objects do not protect against an arbitrary malicious Python process with `object.__setattr__` or interpreter-level mutation; this is an in-process immutable-value API contract, not a security sandbox.
- **Incubate M3/M7 — PLAN/LAB ONLY; DRAFT/HOLD/NO MERGE/NO DEPLOY** until source-owner integration, fresh latest-main compatibility, exact-SHA hosted and permanent VPS passing runs, independent privacy/security approval and explicit human release authority.
