# ScopeDecision immutability acceptance — issue #349

This tests/docs-only acceptance isolates the post-evaluation **value-object mutation** boundary. It does **not** authorize execution, issue a grant, attest tenant ownership, or verify downstream consumers.

## Acceptance contract

- Both denied and allowed decisions returned by the canonical `ScopePolicy.decide` path reject reassignment of `allowed`, `normalized_host`, and `reason`.
- A rejected mutation leaves the full three-field value unchanged.
- Two evaluations return distinct value objects; a failed mutation of one never changes the other or subsequent decisions.
- Directly creating a forged `ScopeDecision(allowed=True, ...)` does not alter the evaluator: **a decision object is not an authorization capability**. Downstream components must validate their own trusted scope, provenance, live grant, risk and execution constraints.

## Execution and ownership

Run offline with `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_decision_immutability_acceptance.py'`. All tested inputs are synthetic loopback or reserved `.test` domains; no hostname is resolved or contacted.

Production changes to `scope.py`, models, activation, executor, authorization issuance, and runtime dispatch are explicitly out of scope. These checks cover only the frozen decision value object and are not a release gate or permanent-VPS attestation. Require exact-head hosted and canonical permanent VPS CI before treating this acceptance as validated. Keep target-active execution disabled without separate explicit authorization.
