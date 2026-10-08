# Target labels are not authorization (offline acceptance contract)

Target.labels is untrusted metadata. A label such as `approved`, `consent:true`, `tenant:owner`, `scope:<host>` or `reapproved` must never substitute for explicit host/network inclusion and an independent current Authorization object where public authorization is required.

The regression module `tests/test_scope_target_label_non_authority_20261008.py` exercises both declared-public-host and declared-public-IP cases, an unknown hostname, an expired grant and an unchanged valid-grant decision. The label tuple may affect presentation, never the allow/deny result.

This test documents existing `ScopePolicy.decide` behavior only; it is not proof that the production executor persists trusted human approval, enforces tenant lineage, or revalidates authorization during dispatch. Production executor remains owned by PR #107. Revocation, provenance and release receipts remain owned by their current PRs.

No real target, socket, DNS resolution, scan, capability dispatch or permission change is performed. Require exact-head hosted and permanent VPS CI plus production-owner review before promotion.
