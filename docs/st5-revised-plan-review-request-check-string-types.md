# ST5 revised-plan review-request exact check strings

## Scope

This acceptance slice is a tests/docs-only child of revised implementation-plan independent review request #517.

- exact parent head: `f8de987ad069a784751a9e38ce258f6a118cea11`
- acceptance issue: #532
- source owner: #517

It is separate from #526/#527, which owns the outer `required_checks` tuple and fixed metadata exactness contract. It does not modify #517 source, #519 strict handoff, #525 builder atomicity, #521 revised-plan sequence hardening, or scope authorization.

## Invariant

Every entry in the typed `required_checks` tuple must be an exact built-in `str` naming the fixed implementation-plan review rubric.

A string subclass is not accepted even when its stored text equals the canonical check text.

## Expected RED at #517

The current dataclass compares the complete `required_checks` tuple to the canonical tuple by value. Tuple equality accepts `str` subclasses whose text equals the canonical values.

The request digest independently writes the fixed canonical rubric, so digest recomputation does not expose a subclass supplied through direct construction.

The regression expects the canonical exact-string control to remain green and the subclass rejection test to fail because no `ValueError` is raised.

## Required source-owner repair

The #517 owner should require `type(item) is str` for every `required_checks` entry, in addition to the exact outer tuple requirement from #526/#527, before rubric equality/digest validation. Reject rather than normalize.

## Safety

Pure in-memory metadata-integrity proof only. No model invocation, target interaction, scanning, tool/remediation/retest execution, deployment, verdict creation, or attack-path mutation.
