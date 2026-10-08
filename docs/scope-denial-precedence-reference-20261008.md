# Scope authorization — offline denial-precedence reference (2026-10-08)

M7/ST5, **proposed contract only**. This independent reference deliberately does not import or alter production executor/policy source. The current executor integration owner is PR #107. Approval/revocation, release receipts, tenant response privacy and lexical input validation belong to other active PRs.

## Proposed internal evaluation order

Before any capability dispatch, reject malformed request type, then evaluate authenticated principal, exact tenant match, active grant, validity window, scope match, permitted capability, and risk ceiling. Every flag must be the literal Boolean `True`; truthy integers, strings, or collections are not sufficient. The first failed check wins, and no downstream check can override it. A fully positive reference result means **conditionally eligible**, never actual authorization.

The error labels in the reference are **internal-only** and MUST NOT be exposed directly on cross-tenant public endpoints: response indistinguishability and audit privacy require review by the tenant-denial owner (#1001). The production policy owner should decide whether these seven checks match actual requirements; the reference must not silently become authority.

## Integration gates

- Trusted issuer verification, exact revision and temporal bounds, live revocation/recheck before each operation, durable audit and cancellation, and tenant isolation are not implemented by these tests.
- Production adoption requires an explicit source-owner review against actual `ScopePolicy` and `ToolExecutor` contracts plus regression tests exercising real code, not this illustrative function.
- Keep inactive / plan-lab only until independent exact-head hosted and permanent VPS proof, reviewer approval, and documented permissions.
- This branch has no real-target contact, active tests, network, scanning, deploy or permission activation.

Reproduce offline: `python -m unittest discover -s tests -p 'test_scope_denial_precedence_reference_20261008.py' -v`.
