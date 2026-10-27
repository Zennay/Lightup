# Independent fail-closed authorization review matrix

Scope: offline review criteria only. Existing issue #364 owns executable membership regression; source owners retain implementation.

| Scenario | Membership | Grant | Expected admission |
| --- | --- | --- | --- |
| Explicit declared public hostname | Yes | Missing | Deny if public authorization required |
| Undeclared public hostname | No | Current and asset-bound | Deny out-of-scope |
| Public IP outside declared CIDRs | No | Current and asset-bound | Deny out-of-scope |
| Malformed or empty hostname | Invalid | Current | INVALID_TARGET |
| Declared host, revoked grant | Yes | Revoked | Deny |
| Declared host, expired grant | Yes | Expired | Deny |
| Declared host, grant for another asset | Yes | Asset mismatch | Deny |
| Undeclared host, public-auth requirement disabled | No | Not required | Deny out-of-scope |

## Acceptance evidence required

1. Pin exact production-owner SHA and fixture shapes; never assume a legacy authorization object is valid against newer owner branches.
2. Assert deny results before any target-capable handler and without network/DNS I/O.
3. Distinguish membership denial from missing authorization and invalid target identity.
4. Prove that configuration switches do not mutate membership or grant records.
5. Record hosted and permanent self-hosted CI separately; no release claim from a queued run.

## Parallel-work boundary

Do not modify existing #364 tests/docs, PR #100 source, durable grant issuance, policy, webapp, activation, remediation, or scanner paths. This matrix is independent reviewer material only; no authority is issued or widened. DRAFT/HOLD until owner approval.
