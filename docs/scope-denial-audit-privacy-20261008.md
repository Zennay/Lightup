# Authorization denial audit privacy — offline acceptance contract

Status: proposed, M7/ST5; **not evidence of runtime enforcement or permission to test a target**.

## Purpose
A rejected authorization request must leave enough evidence for an authorized operator to investigate without turning logs into a tenant-crossing data export or secret store. This contract covers **denial audit output only**, not policy decisions, live grants, scans, execution or release certification.

## Required properties
1. **Deny before logging sensitive inputs:** missing consent, wrong tenant, inactive/revoked grant, undeclared asset, excess risk, and malformed target all remain denied even when audit storage fails.
2. **Bounded fields:** structured events contain event ID, timestamp, tenant-scoped opaque correlation ID, stable denial reason code, and policy version. No raw URL, path, headers, request body, credentials, cookies, bearer token, access token, target inventory or free-form exception trace.
3. **Tenant isolation:** an operator may only read their own tenant's denial events; admin cross-tenant review requires separate explicit authorization and an audit trail.
4. **Untrusted metadata:** interpolated exception messages and arbitrary metadata are never emitted verbatim. Reject unknown event fields at producer boundaries.
5. **Storage failure:** an unavailable audit sink must not change DENY to ALLOW, retry execution, or expose data in fallback stdout/logging.
6. **Retention:** define configurable short retention, purge and access-controlled export; redact before persistence rather than relying on display-time filtering.
7. **Correlation:** use tenant-scoped random opaque IDs and do not expose original secret/target values through reversible encoding or deterministic identifiers.

## Acceptance scenarios
| ID | Input condition | Required observable result |
| --- | --- | --- |
| AUD-01 | wrong tenant | deny; tenant-scoped reason only |
| AUD-02 | revoked grant | deny; no cached authority recovered |
| AUD-03 | token-bearing URL | no raw URL/query persisted |
| AUD-04 | exception includes password | no exception string persisted |
| AUD-05 | sink unavailable | deny without stdout fallback |
| AUD-06 | cross-tenant event lookup | deny without event disclosure |
| AUD-07 | unknown event field | event rejected, deny preserved |
| AUD-08 | malformed target | deny without echoing target |

## Integration gate
Source owner should bind each scenario to exact production paths and negative integration tests. CI proof must pin the tested commit SHA on hosted and permanent self-hosted runners, with independent review. Pure schema tests are **not** proof that a logger, storage engine, or authorization path enforces this contract. No real-target interaction is authorized.
