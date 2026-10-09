# Scope authorization: purpose-binding reference (offline only)

The Current Security, Future Security and Lab Evaluation planes are distinct
assessment purposes. A grant scoped to one purpose MUST NOT implicitly authorize
another. The explicit reference vocabulary is `current-assessment`,
`future-simulation` and `lab-evaluation`; other strings fail closed.

## Proposed production contract

1. An issuer-owned, authenticated grant must bind **tenant**, **request**,
   **purpose**, scope, capabilities, risk and current revision.
2. Admission, queue retry, each live revalidation and atomic dispatch must
   compare the exact effective purpose with the still-active issuer-owned grant.
3. Simulation evidence, Security Twin records, passive-discovery output,
   reports and AI model recommendations must never mint or widen grants.
4. A change of purpose, including movement from Future Security to Current
   Security, requires fresh explicit operator approval and a new validated
   grant; never reinterpret a previous positive decision.
5. Cancellation/revocation/expiry and tenant isolation take precedence over a
   matching purpose. This reference does **not** model those production controls.

## Evidence boundaries

`tests/test_scope_purpose_binding_reference.py` contains a **pure in-memory
reference** with fourteen independent unittest regressions. A positive result means
only that this tiny reference predicate's purpose and identity fields agree;
the reference intentionally restricts identity fields to printable ASCII to avoid\nUnicode confusables and invisible separators; the production owner must decide\na canonical identity grammar. It does not establish authentic provenance, valid consent, authorization for
targets, or permission to execute a capability.

Run offline:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_purpose_binding_reference.py' -v
```

Additional cases require lab grants to remain purpose-isolated and reject malformed\nissuer-side tenant/request identifiers.\n\nNo sockets, DNS, target activity, deployment, scanning or live executor changes.
The production scope-executor owner must decide how to integrate this separate
contract. Keep this PR draft pending exact-head hosted 3.11/3.14 and permanent
VPS checks plus source-owner review.
