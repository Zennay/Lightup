# M7/ST5 scope-authorization: fail-closed incident rehearsal checklist

Status: operator rehearsal **template**; not evidence of any completed test, production approval, deployment, or permission to contact targets.

## Preconditions

- Record incident ID, operator, UTC start, repository SHA, deployment digest, and affected tenant/engagement/grant identifiers **without storing credentials**.
- Confirm the STOP/deny control and audit ledger are operational in an authorized offline or synthetic environment.
- Rehearse with synthetic IDs and a stub executor that records attempted dispatches but never performs target I/O.
- Require a second reviewer for any proposal to reopen dispatch. A green rehearsal cannot substitute for explicit scope authorization.

## Failure-injection acceptance matrix

| Case | Synthetic injected condition | Expected safe outcome | Evidence to capture |
| --- | --- | --- | --- |
| R1 | Authorization resolver unavailable / times out | Deny all TARGET_ACTIVE dispatch; zero handler invocations | Exact SHA; timestamp; denial code; zero-dispatch counter |
| R2 | Grant revoked after run creation, before next step | Next step denied; stale snapshot cannot revive access | Revocation ledger generation; denied step ID |
| R3 | Engagement closed then reopened | Previous grant remains invalid; require new approved grant | Old grant ID; closure/reopen sequence; denial |
| R4 | Live same-ID grant broader than run snapshot | No widening of assets, capabilities, risk or time window | Before/after canonical scope; denied decision |
| R5 | Tenant or engagement mismatched | Deny; no cross-tenant fallback | Tenant/engagement comparison; denied decision |
| R6 | Incident STOP races pending queued work | Stop dominates; queued steps do not dispatch | STOP event ordering; zero post-stop dispatch |
| R7 | Audit/evidence persistence fails | Deny before handler; no success-shaped fallback | Injected ledger error; zero-dispatch counter |
| R8 | Repeated STOP or revoke events | Idempotent denial; never restore authority | Repeated-event log; unchanged denied state |
| R9 | Rollback returns older code/approval snapshot | Prior approval does not authorize resumed dispatch | Old/new SHA; grant generation; denied decision |

## Execution and review

1. Run each scenario in an **offline synthetic harness**. Do not supply customer domains, IPs, credentials, or production tokens.
2. Fail the exercise if *any* scenario dispatches a handler, allows grant widening, or produces an authorization success after STOP, revoke, or ledger outage.
3. Record exact command, artifact hash, runner identity, pass/fail results and timestamps. A planned or queued CI run is **not** passing evidence.
4. Cross-check the result against the production implementation PR's exact head, dependency chain, hosted checks and permanent VPS checks; do not conflate offline reference tests with runtime proof.
5. Attach reviewer decisions and any unresolved defects to the owner PR; leave all authorization gates closed on uncertainty.

## Recovery approval gate

Reopen **only** after (a) fault root cause is resolved, (b) durable state and revocation history are reconciled, (c) every relevant rehearsal case has passing exact-head evidence, (d) the production owner confirms no stale grants or post-stop dispatch, and (e) a separately authorized human approves the exact target scope and validity window. A code rollback, CI success, or emergency override is never itself an authorization grant.
