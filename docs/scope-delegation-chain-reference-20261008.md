# Offline delegation-chain authority reference (2026-10-08)

This document accompanies `tests/test_scope_delegation_chain_reference_20261008.py` and is **not executable authorization**.

## Proposed fail-closed admission boundary

A delegated authorization must retain the exact tenant at every ancestor, prohibit cycles and missing ancestors, and remain no broader than *every* ancestor for assets, capability set and risk ceiling. An inactive ancestor denies the leaf even when the leaf is active. Unknown, malformed or noncanonical grant identities and boolean risk aliases deny. A conditionally positive synthetic example proves only the test oracle's internal consistency.

## Trust and concurrency limitations

The standalone dataclass graph is **caller-supplied** and neither signed nor issuer-authenticated. It is not an authoritative grant ledger; a forged ancestor graph could appear valid. It does not establish signed delegation permission, human approval, time windows, expiry, revocation monotonicity, active cancellation, race freedom, or durable audit evidence. All are required from the production owner before dispatch. An actual product may prohibit delegation entirely; in that case reject every non-root grant and treat this as a negative compatibility contract.

## Parallel ownership and validation

Production `ToolExecutor` remains owned by PR #107, and authorization/revocation integrations by their respective open PRs. This add-only lane changes no source, scopes, permissions, network client, target handler or release workflow. Run offline: `python -m unittest discover -s tests -p 'test_scope_delegation_chain_reference_20261008.py' -v`. Exact-head hosted and canonical permanent VPS evidence plus independent source-owner review are required before integration; no such success is asserted here. Real-target activation remains disabled.
