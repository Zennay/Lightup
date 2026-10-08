# Human approval provenance — offline acceptance contract

Status: proposed, non-production acceptance evidence for M7/ST5 scope-authorization hardening.

## Boundary
Human approval is a distinct, verifiable act. A scope definition, assessment request, logged-in customer session, AI recommendation, prior approval on another revision, and a queued job are **not** substitutes for an authorized reviewer approving the exact assessment revision. Approval must be tenant-bound and must not be inferred from untrusted text.

A valid active-assessment decision must bind tenant, immutable request revision, authorized approver, approved asset set, approved capabilities, risk ceiling, effective time window and authorization/grant lineage. Each component is mandatory for active dispatch. An absent or invalid component denies by default; analysis-only workflows do not acquire active permission from their output.

## Fixture semantics
`tests/fixtures/scope_human_approval_provenance_cases.json` is intentionally a *contract fixture*, not an executable production gate. Each case explicitly names the transition and expected active-dispatch decision. These test vectors describe expected outcomes only; they are **not** proof that the live executor implements them.

### Required regression expectations
1. Requester submits an assessment: pending review denies.
2. Approver authorizes an exact revision in the same tenant: narrowly scoped dispatch may proceed only after every other gate passes.
3. Request content changes after approval: old approval denies.
4. Another tenant reuses a valid-looking approval ID: deny.
5. A requester claims to be an approver in a free-text field: deny.
6. An AI recommendation marks an assessment approved: deny.
7. Approval is revoked before dispatch: deny.
8. An approval record is from a later time or outside effective interval: deny.
9. Approved set excludes an asset or capability: deny.
10. Analysis-only mode remains non-active even with approval.
11. A high-risk request cannot inherit a lower-risk approval.
12. Missing reviewer provenance or authorization lineage: deny.

## Ownership and integration
No production source is modified by this contract. PR #107 retains ToolExecutor and live grant gate ownership. Related revocation transition and queue model work (#983 / #989), release receipts (#982), and approval/assessment source owners remain independent. Once owners integrate, assert decisions at the actual dispatch boundary, with no real targets and a no-op handler, and verify denied attempts produce no dispatch or privileged evidence.

Release still requires exact-head hosted and permanent VPS test receipts plus explicit source-owner review. Do not treat this fixture, local structural checks, or a passing workflow on an unrelated SHA as authorization to activate real targets.
