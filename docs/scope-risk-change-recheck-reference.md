# Authorization risk-change recheck — offline reference

Status: proposed **offline reference**, not production authorization evidence.

## Risk-change boundary

An already-approved request cannot silently change its risk and reuse an earlier approval, even if the revised risk is lower. A change to requested risk must produce a new request revision and obtain fresh approval for that exact revision. Changing tenant or request identity, revoking approval, or narrowing the live cap must fail closed.

At execution admission **and immediately before every dispatch/retry**, the actual production owner must revalidate issuer-owned grant lineage, exact request revision, current authorization, scope and risk, consent, operational window and independent review where applicable. An in-flight action requires cancellation/stop when authority changes. These are **requirements**, not assertions that production code enforces them.

## Proof scope and ownership

`tests/test_scope_risk_change_recheck_reference.py` models nine offline cases using immutable synthetic snapshots. An unchanged sample passing means *conditionally eligible in this illustrative reference function only*, not authorized for a real target. This isolated pair of files does not modify runtime admission, issuance, release receipts, audit, ToolExecutor, policies, target interaction, or authorization state.

Production executor ownership: #107. Human approval provenance: #992. Revocation transitions: #983/#989. Release proof: #982. Review and exact-head hosted plus permanent VPS evidence remain required before any source integration or promotion. No DNS, sockets, scans, active target calls, capability execution or permission widening.
