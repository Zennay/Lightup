# #808 — risk approval tenant-lineage read integrity (offline RED acceptance)

**State:** LightUp Incubate M3/M7. Isolated tests-only branch; **DRAFT / HOLD / NO MERGE / NO DEPLOY**.
**Owner boundary:** `src/lightup/domain.py`, any tenant-resolution SQL, `main`, and other worker PRs are unchanged.

## Proven invariant and known gap

The persisted `risk_approvals.client_id` field is a denormalized label. It is **not** independent authority to read an approval. A tenant-scoped reader must confirm that the referenced `engagements.engagement_id` is owned by that tenant, and that both persisted client IDs agree. Rejection must not write or repair records. Separate operator audit inventory may remain available to an authorized operator, subject to its own policy.

On main at `05b80319cd0581fed21fe9d8f565bcb0a56cd2df`, the client-wide query in `DomainStore.list_risk_approvals()` filters only `risk_approvals.client_id`. The explicitly engagement-scoped query checks engagement tenant ownership but does **not** additionally check the approval row's duplicated client ID. This is an independently reproducible synthetic cross-tenant disclosure *risk* after persisted-row corruption, **not** evidence of a real incident or a live exploit.

## Fixture and acceptance matrix

`tests/test_scope_808_risk_approval_tenant_lineage_sqlite_20261013.py` uses an isolated temporary on-disk SQLite database, the real unchanged `DomainStore` methods, two synthetic clients with one engagement and one risk approval each, and one direct synthetic test-only UPDATE of the duplicated approval tenant field.

- Five ordinary PASS controls: two normal tenant listings; two explicit engagement checks; foreign engagement denial; operator-wide listing; and unmodified persisted database after ordinary reads.
- Five **intentional unresolved expected failures (RED)**: corrupt A→B tenant label must not expose A's approval to B; A's explicit engagement list must not expose a mismatched approval; B's canonical approval must remain visible while the corrupt A approval is excluded; a row that points to B's engagement while keeping A's client label must be hidden from A; and an orphaned approval with no owning engagement must be excluded.
- Three additional ordinary PASS controls after corruption: foreign engagement denial remains enforced; all synthetic rejected/read-only operations leave the persisted row snapshot unchanged; and a canonical B approval remains visible if an unrelated synthetic A engagement is deleted using a deliberately FK-disabled offline fixture connection.

Run from repo root (installed project dependencies available):

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_808_risk_approval_tenant_lineage_sqlite_20261013.py' -v
```

**Interpretation:** `OK (expected failures=5)` is **not security pass**. It means five source-owner denial cases remain unresolved. On production integration, remove `@unittest.expectedFailure` one by one only when the repaired installed query genuinely passes the corresponding requirement without weakening it; rerun full old/new tests and check unrelated operator/tenant read paths. If a corrected query makes the RED cases unexpectedly succeed, CI should flag `unexpected success` until the markers are removed with reviewer approval.

## Release and collision gates

Source owner must implement coherent tenant/engagement revalidation **inside the installed read path**, preserving filters, meaningful operator-audit behavior, and read-only failure. Need independent privacy/security review, current-main compatibility, exact commit SHA hosted Python 3.11 and 3.14 CI, separate permanently registered VPS runner CI, and explicit human approval. No test or documentation in this branch authorizes a scan, target interaction, tenant access, grant, remediation, retest, production migration, merge or deployment.

## W3 — operator read-path split
Three more synthetic real SQLite acceptance scenarios: the operator-wide audit inventory retains corrupt approvals **without rewriting state** (ordinary green), but operator-explicit engagement reads must reject a relabelled tenant and an A approval retargeted to B's engagement (**2 additional intentionally unresolved expected RED** against main). Total now **16 methods: 9 ordinary controls plus 7 unresolved expected RED**. Green suite with seven expected failures is NOT an installed security fix.
