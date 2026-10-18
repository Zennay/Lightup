# Request-to-grant operator workflow · 18 October 2026

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD — no production authorization.**

## Actual product source
The normal authenticated operator client page now displays original stored approved authorized-assessment requests for that client. The grant form requires the operator to select the exact original approved request ID; when there is no approved request, the form is not shown. Selected ID, stored requester/reviewer identity, approved exact assets and risk are checked by the original atomic domain source before issuance. A selectable request does not imply that a proposed grant is compatible or is client consent.

Unmodified domain source and new grant_request_binding.py come from original independent source owner PR #1570 at exact source head ddafadd91759fecb82a8ac662d546a3be8177b51. Original persisted client/engagement lineage, real separately authenticated client requester and operator decision, transactional request→grant binding and read-time revocation-sensitive lineage checks remain intact. No target execution authority is granted.

Original web owner PR #182's strict risk and validity admission is composed without changing its branch: no default or clamped maximum risk, requested risk or validity days, and exact approve/reject or approve/deny operator input is needed to change authorization state. The integrated base #1613 continues original cookie admission, opaque domain errors, operator portal read-only boundary and atomic Unicode-safe tenant CSV.

## Provenance and hold
Base original own combined source PR #1613 head ee8edb6725c34bc8258a689eb3cfc69584b9733d. The only new or changed source paths are src/lightup/domain.py, src/lightup/grant_request_binding.py, src/lightup/webapp/app.py and this new document. Original owner branches and tests/workflows unchanged. Connected zSSH vps-bb300bba isolated checkout exact pre-document HEAD fc47ed7d5282f6f6e78737fe16334f7bb04a5d42 compiled seven integrated Python product modules cleanly. No QA/tests authored, edited or manually run.

Do not merge/deploy before original exact-head hosted and permanently named VPS CI, domain/web/auth/security/privacy owner review, real separate client/operator authorization and at-action revocation, and explicit HUMAN GO. No active grants, target interaction, scanner or release occurred.