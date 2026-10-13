# #1093 — independent opt-in destination role metadata preview

**INCUBATE M3/M7 — PLAN/LAB ONLY. DRAFT / HOLD / NO MERGE / NO DEPLOY.**

This additive, opt-in module addresses issue #1093 independently of the existing branch-only metadata reference. It binds a set of typed HOST, ENDPOINT, PORT and PORT_SET roles to an **exact registered ToolDefinition** and verifies the argument shape, role/kind pairings, ambiguous authorities, and registration snapshots. No other worker paths, production ToolExecutor, policy, registry or workflows are modified.

The preview always returns a frozen `status=hold` receipt with `authorization_verified=false`, `permit_issued=false`, `execution_enabled=false`, `release_approved=false`. It never dispatches a handler, resolves DNS, calls a policy or grant resolver, issues a grant, writes evidence, or contacts a target. The separate #1093 acceptance branch remains unchanged.

Real tool execution **must not** use this preview as approval. Actual source-owner integration still requires current trusted same-engagement/tenant grant, capability, risk, window, revocation, same-authorized-asset destination matching (including DNS and redirects), safe retries, target-scoped egress and pre-I/O revalidation. The optional shape review proves none of these. Optional module is not installed anywhere in the executable ingress.

Unit tests: `PYTHONPATH=src python -m unittest discover -s tests -v`. Require exact-head hosted Python 3.11/3.14 and independent registered permanent VPS Python 3.11/3.14 proofs, source/security/privacy review, latest-main composition and human release decision. CI green never grants execution authority. All test inputs are local/synthetic; no customer data, scanners, real targets, deployments or grant issuance.
