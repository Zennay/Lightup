# Scope authorization — independent reviewer separation (offline contract)

Status: **proposed acceptance semantics only**. No runtime authority is granted by this document.

## Boundary

For a high-risk or active capability activation, a request creator must not approve their own request. A trusted operator approval must bind the exact tenant, request ID, request revision, requested scope digest, risk ceiling and reviewer identity. The reviewer must be different from the requester, using canonical immutable principal IDs (not display names). Reject missing, malformed or boolean IDs, stale revisions, mismatched tenants, mismatched scope digests, inactive approvals, and replays. A changed request requires fresh review. A second review is required where policy calls for it; two signatures from the same reviewer never count as two people.

A system administrator identity or UI role label must not implicitly waive independence; only a separately documented, explicit break-glass process may do so, and this contract defines **no** break-glass bypass.

## Handoff

The standalone reference predicate in `tests/test_scope_approval_separation_20261008.py` illustrates these requirements with inert local data. It does not query an issuer, confirm trusted signatures, authenticate people, provide a real approval service, or exercise ToolExecutor. Production owner #107 and human-approval provenance owner #992 must implement and independently test issuer-backed enforcement. Audit decisions should record stable IDs and minimal necessary metadata without emitting secrets.

Keep the feature in M7/ST5 plan/lab-only. No target contact, scanning, capabilities, network access or activation is authorized by these files. Before integration require owner review, exact-head hosted and permanent VPS tests, and an explicit approval to promote.
