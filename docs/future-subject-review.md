# Future subject review API

`lightup.future_subject_review.review_future_subjects` creates a read-only,
tenant-scoped view of a candidate-bound future twin. It is a backend API for a
later portal/JSON export integration; this slice does not add a web route.

```python
from lightup.future_subject_review import review_future_subjects

# context must originate from the authenticated user's session.
# Operators must explicitly select a client; client users are tenant-bound.
review = review_future_subjects(
    future, evidence_store, context, client_id=selected_client_id,
)
payload = review.as_dict()  # detached and JSON-serializable
```

The caller must authenticate the user before constructing `AccessContext`;
passing a role string supplied by a browser is not authentication.

## Review states

| Candidate binding | Subject decision | Next action |
| --- | --- | --- |
| No candidate | Pending | Supply a candidate mapping |
| Multiple candidates | Pending | Disambiguate the mapping |
| Single candidate | Pending | Record an explicit evidence-backed review |
| Single candidate | Verified | Await future-effect graph resolution |

Each item includes the change ID, source path, signal summary, candidate IDs,
verified subject/decision/basis when present, and evidence references. Raw
ledger payloads are not copied into the result. Results are deterministic and
immutable; `as_dict()` yields a separate value for serialization.

The report names the exact twin ID/version and ChangeSet. It uses the same
canonical-state and live-ledger validation as the resolver's write path.
Deleted evidence, inconsistent provenance, partial decisions, and stale
candidate lineage raise instead of generating a partly trusted report.
Cross-tenant requests fail before snapshot validation or evidence lookup.

`subject_review_complete` describes only whether all represented changes have
explicit subject decisions. Empty reports do not count as complete.
`future_semantics` remains `unresolved` and `security_verdict` is always
`not_evaluated`, including when every subject has been reviewed. This is not
an authorization decision, an attack-path result, or approval to deploy.

A subsequent unchanged snapshot can be read using the existing decision.
That does not replay the original write: recording a new decision still
requires evidence bound to its exact input snapshot version.
