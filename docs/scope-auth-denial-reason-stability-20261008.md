# Scope authorization denial-reason stability (offline acceptance)

Phase: M7/ST5. Independent review-only contract, 2026-10-08.

Authorization outcomes are not permissions. A changed diagnostic reason must never
convert a denial into approval, authorize a broader target or cause execution.

## Invariants

1. Every rejected evaluation remains `allowed=false` through persistence, logging,
   serialization, display, retries and evidence export.
2. Human-readable labels, unknown reasons, malformed reason values and localized
   strings are untrusted diagnostics, never authorization inputs.
3. A stale denial cannot be replayed as approval after a grant is changed, expired,
   revoked, or narrowed; any requested execution requires a fresh authoritative check.
4. Unknown or missing reason codes may map to a generic denial label, not to
   an allowed state; diagnostics must not include secrets or asset metadata.
5. An authorized control case may be approved only by an independent current grant
   and exact target/capability/risk admission, not by its reason label.

The fixture is an **acceptance specification**, not a production security test.
Domain grant owner, ExecutionPolicy #100 and ToolExecutor #107 retain source ownership.
Integrators should exercise each case against the real persisted/reloaded decision
and executor denial path with paired positive controls. Until that integration,
no production-hardening or CI-green claim follows from fixture checks.

No targets, network/DNS, scans, active execution, grant changes or deployment.
