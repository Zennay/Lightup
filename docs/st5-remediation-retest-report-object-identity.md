# ST5 remediation/retest report object identity

Issue: #844

## Boundary

`build_future_security_remediation_retest_plan()` is a live evidence-to-remediation
consumer. It rebuilds the ST4 security-delta report from the exact preview,
proposal, verified resolutions, run contexts and live `StateStore`, then
compares that rebuild with the caller-supplied report.

That comparison must not trust polymorphic behavior from the caller object.

Canonical ST4 production emits an exact
`FutureAttackPathSecurityDeltaReport`. A subclass is producer-impossible and
must fail closed before equality, inequality, field reads used for remediation
planning, or any other caller-overridable behavior participates in the
boundary.

## Why this matters

On the current source shape the stale/tampered check is effectively:

```python
live_report = build_future_attack_path_security_delta_report(...)
if report != live_report:
    raise ValueError(...)
```

Because the caller-owned `report` is the left operand, a subclass can override
`__ne__` and suppress the mismatch. The builder then consumes the caller
object's `items` and can derive different remediation/retest next actions than
the live ST4 lineage supports.

This is not a target-execution bypass. It is an evidence/remediation integrity
failure at the point where verified evidence is translated into follow-up
planning.

## Acceptance contract

The regression pack requires:

- an exact canonical ST4 report remains accepted;
- any report subclass is rejected with `ValueError` before polymorphic
  comparison runs;
- an equality-spoofing subclass cannot replace an `INTRODUCED` classification
  with `IMPROVED` and thereby switch from remediation-plus-retest planning to
  verification-only retest planning;
- rejected caller-owned report state remains unchanged;
- live runs, capability leases and evidence rows remain unchanged;
- execution, deployment and attack-path mutation authority stays false.

## Expected state

Expected RED until the remediation/retest builder source owner adds an exact
runtime identity guard such as:

```python
if type(report) is not FutureAttackPathSecurityDeltaReport:
    raise ValueError(
        "report must be an exact FutureAttackPathSecurityDeltaReport"
    )
```

The guard belongs before the live rebuild comparison so caller-defined equality
or inequality cannot participate in admission.

## Collision boundary

This branch is tests/docs only.

It does not modify:

- `src/lightup/future_security_remediation_retest_plan.py`;
- #190 strict handoff ownership;
- #325 direct plan/item construction ownership;
- #328 ST4 report direct-construction ownership;
- #350 remediation/retest builder atomicity ownership;
- remediation text/reviewer/implementation-planning producers or consumers;
- scope authorization, target-capable workers, deployment, verdict or
  attack-path mutation code.

## Safety

Pure deterministic in-process integrity proof. No model call, DNS/network I/O,
target interaction, evidence collection, capability execution,
remediation/retest execution, deployment, security verdict creation or
attack-path mutation.
