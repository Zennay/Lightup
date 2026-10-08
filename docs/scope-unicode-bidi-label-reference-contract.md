# Scope authorization: Unicode display-label deception (offline reference)

**Status:** M7/ST5 reference only; no production authority or activation.

## Trust boundary

Tenant names, grant titles, actor names, approval notes and audit labels may be untrusted presentation data. Rendering bidi controls, control characters, mixed canonical forms or embedded line separators can make a reviewer see different text from the stored identity. A visually convincing label **never** authorizes an operation.

The companion pure-stdlib offline reference denies Unicode bidi formatting controls (including isolates), general Unicode control/format/surrogate/private/unassigned categories, line/paragraph separators, non-NFC strings, oversized/empty strings and non-exact-string input types. No network or runtime service is used.

## Production-owner acceptance

1. Keep canonical, issuer-owned opaque IDs for tenant, subject, target, grant and capability comparisons. Never resolve identities or approvals from display labels.
2. Validate all user-controlled labels at ingress; encode or neutralize hostile characters in UI, exports, logs and operator approval screens; preserve safe identity mapping.
3. Verify UI/API/audit alignment using synthetic fixtures, including RTL override and isolates, normalization aliases, newline injection and cross-tenant visual similarity.
4. Reject or safely encode unsafe labels with no queue/enqueue/dispatch side effects. Test same on retry and asynchronous dispatch.
5. Require human review and exact-head hosted and permanent VPS evidence before integration or target activation.

## Limits

These tests validate a **standalone demonstration validator**, not LightUp production. A passing label is not a valid grant; visual confusables and mixed-script spoofing may require a separate product-specific policy. The live executor remains owned by #107. No real target, socket, DNS, scanner, token issuance, new grant or deployment is involved.
