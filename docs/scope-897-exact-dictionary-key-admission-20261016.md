# #897 — Exact offline risk-review dictionary keys before equality

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is an unwired local reference, never an approval or product source patch.

## Security contract and action

The prior standalone risk-record reviewer used `record.keys() == _FIELDS` on an exact outer built-in `dict` before verifying that **every key** was a built-in `str`. A `str` subclass can remain equal to a canonical field name while overriding `__eq__`/`__hash__`, and a custom object can spoof a required key's hash/equality. Even in an offline REVIEW_ONLY helper, caller methods should not run before admission.

On a separate child pinned at exact existing reference HEAD `cb67139d630af625dd15c5d47a9ee577bb9d22bd`:

- First require exact outer `dict` and exact number of fields.
- Next require `type(key) is str` for **all** keys via built-in dict iteration, before equality checks.
- Only then compare key-set contents and fetch field values; existing exact type, ID, requester/reviewer, `PENDING` audit, no-self-review and no-authority checks remain unchanged.
- Add two synthetic tracked-key regression methods that assert `HOLD` and **zero invocations of `__eq__`/`__hash__`** during review, retaining all six explicit false authority flags.

The branch changes only the own opt-in test helper and its unit test file and adds this new receipt. It does not touch `DomainStore.decide_risk_elevation`, original #791/#796/#807 installed-source acceptance or any other-worker branch.

## Proof posture and owner handoff

**Tests are newly authored, not yet executed on the actual GitHub child HEAD or trusted self-hosted runner.** GitHub diff/commit checks alone are not test PASS. Original #146 owner must still fix canonical approval SQL identity, persisted requester provenance and stale PENDING audit before mutation. Self-hosted runner #1144 remains a separate queue/registration investigation; do not create duplicate canonical jobs. Release needs owner review, exact-HEAD hosted + registered VPS, independent security/privacy, verified customer/operator consent and explicit human GO.

This helper neither writes live SQLite nor issues grants, makes decisions, opens sockets, dispatches target-capable handlers, scans, deploys or changes release state.

## Additional CLI opt-in boundary on the same child

The isolated `main(argv)` compared any programmatic caller object with the opt-in flag list before exact argv typing, which could invoke attacker-defined equality and read stdin on a forged match. It now requires an exact built-in list with exactly one exact built-in string matching the literal flag before reading stdin. Two additional tests pass a `__class__`-spoofed argv and a string-subclass option with forged comparison and a stdin object that explodes on access; the required result is HOLD/exit2, zero comparison calls and six false authority flags.

**These new test methods have NOT been executed on the new HEAD**. Original #146 production source remains unchanged and its risk-approval REDs are unresolved. All work remains branch-only, no CI dispatch while the shared runner queue is held.
