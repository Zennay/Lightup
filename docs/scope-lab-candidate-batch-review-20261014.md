# All-or-none offline lab candidate dispatch batch preview

This optional `review_lab_candidate_batch(ledger, items)` inspects 1–32 exact `LabCandidateReviewItem` records, each containing the **actual** LightUp `RunContext`, `ToolCall` and `ToolDefinition`. It uses the independent single-item candidate/real-model consistency reviewer for every entry, then applies batch-level HOLD for duplicate client+run identities or the same casefolded declared lab asset appearing under different tenants. It deliberately does **not** resolve DNS aliases or prove asset ownership.

There is no partial “approved” packet: on *any* error or ambiguity, the whole review is `HOLD` and `reviewable_items=0`. A matching local lab-only synthetic batch can be shown as `REVIEW_ONLY` with a **non-authorizing reviewable count**, never with a permit. Every receipt always returns `authorization_verified=false`, `permit_issued=false`, `execution_enabled=false`, `merge_approved=false`, `release_approved=false`. No handler, active ToolExecutor or network is called. A previous green single-item review does not authorize a later batch or imply transactional permission: SQLite remains untrusted and can change between reads.

16 real, disposable SQLite + actual LightUp-model regression methods cover atomic rejection of the second/third item, duplicate run identity, tenant collisions, casefold aliases, invalid collection types/counts, expired/revoked/frozen candidate, parametrized destinations, positive disjoint fictional records and zero network execution.

Still missing: authenticated operator role/provenance, independent verified consent and target ownership, trusted immutable approval ledger, physical lab/egress isolation and original [ToolExecutor owner #107](https://github.com/Zennay/Lightup/pull/107) + [step-up owner #1172](https://github.com/Zennay/Lightup/pull/1172) integration. **INCUBATE M3/M7 · PLAN/LAB ONLY · NO REAL SCANS · NO PERMIT · NO DEPLOY**.

Run `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_lab_candidate_batch_review.py' -v` for isolated tests.
