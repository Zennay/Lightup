# #880: coherent durable assessment decision provenance (opt-in)

**Stage:** LightUp Incubate M3/M7 PLAN/LAB ONLY. DRAFT/HOLD/NO MERGE/NO DEPLOY. No real client, grant issuance, target, network, scan, testing, remediation or deployed security claim.

## Open source issue and anti-collision
[Open #880](https://github.com/Zennay/Lightup/issues/880) documents that `DomainStore._request_from_row` currently reconstructs approved/rejected or submitted/under-review requests without validating the relationship among `status`, `decided_by` and `decided_at`. Bad read provenance must never become authorization provenance for #177 request→grant binding.

Original domain producer/source ownership stays with #133/#177 and request intake/read #654/#875/#876/#877/#878. This branch is based directly on immutable current `main` `05b80319cd0581fed21fe9d8f565bcb0a56cd2df`, adds ONLY the new opt-in reference, independent tests and this doc; no original `domain.py`, webapp, grant/activation, evidence, target, main or parallel-worker modifications.

## Concrete implementation
- `src/lightup/request_decision_provenance_optin.py`: **uninstalled**, read-only, **non-authorizing** record integrity sidecar. Checks exact `AssessmentRequestRecord` and `RequestStatus`. SUBMITTED / UNDER_REVIEW must have both decision fields NULL; APPROVED / REJECTED must have builtin nonblank actor and builtin ISO timestamp with a timezone-aware offset. Returns the unchanged original record or a generic `TypeError/ValueError`; no DB changes, grants or permits.
- `tests/test_scope_880_decision_provenance_sqlite_20261012.py`: **15 real synthetic SQLite** source acceptance methods, including **6 deliberate expected RED** for currently unvalidated corrupt default producer reads (approved missing actor, rejected missing time, stale submitted/under-review, bad/naive timestamp). Green opt-in tests demonstrate no mutation, controlled refusal, valid source-generated approved/rejected and open state roundtrips, cross-tenant denial, no implicit grant or engagement creation.

## Owner acceptance
Required producer repair is in `DomainStore._request_from_row`: atomic fail-closed, read-only validation of status, actor, decision timestamp with exact canonical types and valid timezone-aware timestamp. Preserve original rows and keep approval source/reviewer authority, grant issuance and tenant checks independent. Verify all selectors, actual web flow, revalidation to client/grant/engagement and durable decision timestamps. Convert six intentional expected RED canaries to *ordinary passing negative tests* after the original owner integrates the fix.

Require exact final SHA GitHub-hosted Python 3.11/3.14 full suites, **separately registered permanent self-hosted VPS CI**, independent tenant/privacy/security review, safe current-main composition and explicit human release. This branch is DRAFT/HOLD, never default-authorizing or a substitute for approval. Keep #880 OPEN.

Synthetic reproduction:
```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_880_decision_provenance_sqlite_20261012.py' -v
```
