# #1023: exact-order authorization-envelope preflight (synthetic acceptance)

**Stage:** LightUp Incubate M3/M7 PLAN/LAB ONLY. **DRAFT/HOLD — NO MERGE, DEPLOY, GRANT OR TARGET DISPATCH.**

## Ownership and source boundary

- Parent: [DRAFT #1012](https://github.com/Zennay/Lightup/pull/1012), fixed exact SHA `cb4863a240741750ff2be2c9313913f3ea940f6b`. Its uninstalled `bounded_envelope` reference is shape validation only, not a grant verifier.
- This child adds ONLY this document and `tests/test_scope_1023_envelope_preflight_order_20261012.py`. It does not modify the source/reference owned by #1012, executor/domain/#107, JSON semantics/#1002, human-review matrix/#1062 or any other worker's branch.
- The test patch-probes `json.loads` to show that invalid budget configuration, oversize bytes and wrong raw-body types are rejected *before* invoking a parser. It checks inclusive ceilings, duplicate encoded keys, invalid UTF-8, nonfinite numbers and unchanged caller buffers.
- Positive shape eligibility explicitly **does not** verify issuer, tenant, operator, ownership, scope, allowed risk, purpose, approval, revocation, session, execution or live evidence. A syntactically eligible fake approval is deliberately included as a *non-authorizing positive control*.

## Owner-gated integration contract (not implemented here)

1. Inventory actual HTTP/CLI/queue ingestion points and determine which, if any, admit raw untrusted authorization envelopes. Current `ToolExecutor` receives structured arguments; do not assume every route needs envelope JSON or invent a production endpoint.
2. For each real parser intake, enforce positive exact-int budgets and byte limit **before** UTF-8 decoding or JSON allocation; enforce depth/node and duplicate-key acceptance, errors denying with no partial write.
3. Verify immutable, separately trusted issuer, tenant, engagement, target asset, capability, risk, time, revocation/STOP, operator step-up and explicit human authorization; parse success is NEVER authority.
4. Validate real in-process entrypoint and synthetic disposable SQLite negative/positive tests with zero handler/evidence/queue/grant side effects on rejection. Include concurrent/revoked and latest-main composition checks.
5. Source owner #107 and security/privacy reviewer must approve the integration; obtain exact-head GitHub-hosted Python 3.11/3.14 **and separately registered permanent VPS** successful results. No queued run or green reference test substitutes for production proof.

## Validation

Run from this stacked child branch:

```sh
python -m unittest discover -s tests -p 'test_scope_1023_envelope_preflight_order_20261012.py' -v
```

The suite tests the **offline #1012 predicate only**; it does not establish installed ingress protection, process memory safety, authorization enforcement or release readiness. Tests require no DNS, sockets, remote targets or live credentials. Keep [issue #1023](https://github.com/Zennay/Lightup/issues/1023) open until source-owner integration and release gates are genuinely met.
