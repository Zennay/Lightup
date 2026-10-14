# M7/ST5 authorization promotion matrix (owner-gated)

Status: **non-authoritative review artifact**. No production authorization is granted by this document. Do not deploy active-target functionality based on offline reference tests.

## Ownership and collision boundary
- Production execution/admission stays with existing owners of PR #107 and PR #100.
- Bounded-envelope reference is tracked by #1012 / #1023; other scope risk and interaction identity regressions are tracked by #987 / #986.
- This file is a checklist only: no edits to execution policy, ToolExecutor, StateStore, or shared runner configuration.

## Mandatory promotion evidence

| Gate | Positive control | Mandatory deny / malformed control | Side-effect assertion |
| --- | --- | --- | --- |
| Envelope resource admission | Within configured exact-integer byte/depth/node ceilings | Oversize before UTF-8 decode, invalid UTF-8/BOM, duplicate keys incl. escaped aliases, JSON trailing data, non-object root, NaN/Infinity/exponent overflow, excessive depth/nodes, bool/nonpositive budgets | Zero grant writes, queue entries, target I/O |
| Identity | Canonical issuer, tenant, operator, asset and capability | Empty/foreign tenant, unknown issuer, cross-tenant authorization or asset, alias/confusable enum type | Zero handler calls and evidence writes |
| Interaction and risk | Canonical enum members for intended mode | Unknown interaction values (no active-path fallthrough); numeric/bool/foreign-enum risk values (no permissive comparison) | Zero active capability calls |
| Temporal validity | Trusted, current, timezone-consistent validity window | Expired/not-yet-valid, malformed time fields, live grant expanding initial run window | No execution |
| Revocation / stop | Valid same-id live grant is still active and STOP is false | Revoked/deleted grant; STOP or emergency override; resolver missing or returns wrong object type | Denial dominates and does not create work |
| Monotonic live authority | Same-id live grant is equal or narrower than run snapshot | Added asset/capability, increased risk, widened validity window, relaxed exclusions | No dispatch, no persisted verdict |
| Evidence binding | Successful *authorized* dry-run binds correct run, grant, tenant, capability | Forged or cross-run ledger, reused/expired evidence, mismatched resolver/grant | No evidence accepted or promoted |
| Audit safety | Denial reason is bounded, redacted and attributable to run ID | Grant token/secret, raw customer payload or sensitive credential in logs | Denials reveal no secrets |

## Exact-head execution protocol
1. Owner records canonical base SHA, branch/head SHA, and each test command **before** initiating CI.
2. Run offline local/hosted tests for both positive and negative cases without external targets; record structured output and exit codes.
3. Run canonical permanent self-hosted VPS CI for the *same head SHA*; avoid claiming a prior green run validates a newer commit.
4. Verify no production changes outside the declared owner files and no authority-widening policy change.
5. Confirm real target execution is disabled and approval remains explicitly human-controlled until signed scope evidence exists.
6. Review failing/expected-RED reference contracts separately. An expected-RED contract cannot count as production green.
7. Only the production source owner can absorb references and promote them; keep sidecar PRs draft until integration and proof exist.

## Stop conditions
- Any missing canonical test, failing security invariant, incomplete runner evidence or SHA mismatch: **do not merge/promote**.
- Missing revocation or STOP proof: **deny** regardless of other positives.
- A parser passing shape checks does **not** imply a valid grant, and grant validation does **not** imply permission to scan external systems.

Related tracking: #107, #100, #986, #987, #1012, #1023, #1039, #948–#954.
