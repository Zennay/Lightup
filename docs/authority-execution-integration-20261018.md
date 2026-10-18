# LightUp execution and authority guard composition

**18 October 2026 · INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**

## Material source integration
This branch builds on the fully integrated, still HELD original request→operator grant binding source and default web/tenant boundary in PR #1614. It now composes three exact previously authored original production modules without changing their owner branches:
- Original PR #1601 `src/lightup/execution_policy.py` — canonical request/interaction/capability/risk/auth shapes, defensive snapshot and fresh UTC expiration denial before positive target-active policy outcome.
- Original PR #1598 `src/lightup/activation.py` — stable target/authorization identity at issuance, canonical scope decision and capability checks, explicit LAB/authorized provenance and issuance-time clock check.
- Original PR #1599 `src/lightup/ai/orchestration.py` — canonical tool registry, argument and handler admission; duplicate/ambiguous arguments, forged evidence objects and nonfinite numeric metadata refused before dispatch.

## Product path
The normal web operator must bind a genuine persisted approved client request to a grant (parent #1614); the existing application and tool policy cannot turn malformed in-memory authorization/request/target metadata into a valid active decision or execution permit; and tool registration and audit input fail closed before existing handlers. These source policies do not authenticate real client or operator consent or perform durable revocation-at-use. Existing ToolExecutor and future runner still need independent true durable authority checks. No new scanner, target runner, grant issuance, active use or permission is introduced.

## Source custody and verification
Parent PR #1614 exact head b75e6a3b57855f3c639a8bdb1b4a6c608c8c178d. Source imported without edits from exact original owner heads: #1601 ea53b84655582a3e1040c6d3f70f620efb2445c3, #1598 942df00b02ab51256631ba8ded26c49668c3c9d5, and #1599 19f3fced9a750235def8a9db4a25b0369bb9805e. All three original owner branches remain intact.
Connected zSSH `vps-bb300bba`: isolated checkout at source head 8a5b63e0e05ec70a9af05b817f33626bddfc993d, Python source compile and imports of actual activation/execution/orchestration/domain/production web classes successful, clean working tree. No tests/QA/regression suites written, changed or manually executed.

Original automatic hosted and permanently registered named VPS CI, intentional source-owner review of prior RED contracts, separate real authenticated client/operator consent + action-time revocation, independent security/privacy approval and explicit HUMAN GO are mandatory. Do not merge into main, deploy, issue actual grants, scan, dispatch active handlers or claim release. This branch is candidate source for future owner-reviewed integration only.