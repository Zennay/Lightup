# Remediation evidence export: tenant-bound release gate (offline contract)

## Scope and ownership
This is a standalone, non-authoritative acceptance contract. It does not modify the existing remediation receipt, temporal lineage or artifact manifest reference PRs (#1065, #1066, #1067), nor production ledger, review, authorization or deployment code.

## Export preconditions
A tenant-bound remediation evidence export MUST fail closed unless ALL conditions are met:

1. The authenticated caller supplies a canonical tenant identity, independent of the evidence body. Self-asserted tenant identifiers are never authority.
2. The requested finding, remediation and retest belong to that exact tenant. Cross-tenant and mixed-tenant bundles are rejected atomically without partial output.
3. A reviewer independent of evidence submission has approved the exact requested export revision. Previous or revoked review results cannot be reused.
4. Evidence identities and digest references are stable, exact and already verified against immutable source bytes. Digest shape alone is not proof of provenance.
5. The remediation/retest chronology is strictly validated and bound to the same finding and assessment revision; no time-of-check/time-of-use substitution.
6. Redaction is performed by the trusted server, not inferred from a client-provided redacted flag. Export excludes credentials, tokens, raw target data, private URLs and unapproved personal information.
7. Unknown fields and unsupported export formats are rejected by default. Every denial results in zero externally visible partial bytes and zero state mutation.
8. A successful export records only the minimum necessary tenant-scoped audit metadata; it does not create findings, alter verdicts, approve execution or contact targets.

## Synthetic negative acceptance matrix
- Tenant A reviewer + Tenant B remediation => deny.
- Correct tenant + foreign finding identity => deny.
- Correct tenant + stale/revoked review => deny.
- Correct tenant + mismatched artifact hash => deny.
- Correct tenant + unverified remediation-before-observation or retest-before-remediation => deny.
- Correct tenant + explicit client redacted=true without trusted redaction proof => deny.
- Correct tenant + mixed approved/unapproved evidence => atomic deny.
- Correct tenant + unknown freeform field carrying raw secret => deny.
- Correct tenant + destination or storage failure => no partial export, safe error.

## Production integration gate
The production source owner must wire these requirements into the authenticated export pathway, add integration tests for trust boundaries, and obtain exact-head hosted and canonical permanent VPS green proof before considering promotion. Reference acceptance is not production enforcement. No real targets, network activity, scanning, remediation execution or permission widening are authorized by this document.
