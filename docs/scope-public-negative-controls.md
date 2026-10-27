# Public-target scope authorization: negative controls

These offline regressions establish that **asset allowlisting is not authorization**.
They exercise the existing `ScopePolicy.decide` contract without DNS, sockets,
real-target interaction, credential use, or changing production policies.

## Expected decisions

| Scenario | Expected result |
| --- | --- |
| Explicit hostname or network, no grant | Denied: `authorization_missing` |
| Listed asset with future or expired grant | Denied: `authorization_expired` |
| Current grant but unlisted public hostname/IP | Denied: `out_of_scope` |
| Approval-looking target labels without a grant | Denied: `authorization_missing` |
| Explicitly listed asset plus current grant | Allowed by scope layer only |
| Unlisted public hostname under default policy | Denied: `out_of_scope` |

A scope-layer allow result is **not** a permit for active testing. Execution still
requires the project activation, risk, engagement and tool-level policy checks;
this test module intentionally does not bypass or simulate those approvals.

## Test command

```sh
PYTHONPATH=src python -m unittest tests.test_scope_public_negative_controls -v
```

The test uses only reserved documentation IP ranges and fictitious domain names.
No branch shared with other workers was changed. This is a regression coverage
addition, not a change to production execution behavior.
