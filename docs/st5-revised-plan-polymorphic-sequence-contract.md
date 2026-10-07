# ST5 revised-plan polymorphic sequence fail-closed contract

Issue: #518  
Parent ownership: #511  
Exact parent head: `f3948422929bb9d6525cb2df263c008c763de3f1`

## Purpose

The strict revised implementation-plan handoff already requires an exact built-in
`dict` at the top level and exact built-in `dict` values for each plan item.
Its nested sequence guards, however, use `isinstance(value, (list, tuple))`.
That admits user-defined sequence subclasses whose stored contents can differ
from the contents exposed by overridden iteration.

Persisted-input validation must not trust polymorphic container behavior. The
parser-visible values and the caller-owned stored object must have one exact
meaning.

## Required invariant

For `plan_items`, `assumptions`, and `unresolved_questions`:

- accept only the explicitly supported built-in container types;
- reject subclasses before reading length, iteration, indexing, normalization,
  digest recomputation, or any later live-lineage work;
- never coerce a subclass into a canonical container as a repair;
- never mutate the caller-owned object on success or rejection.

The canonical built-in sequence control remains accepted.

## Expected RED on #511

The regression uses a `list` subclass that stores invalid content but overrides
iteration to present canonical values whose digest already matches the artifact.
At #511 head, the parser accepts the polymorphic container because the
`isinstance` guard passes and subsequent iteration sees only the presented
values.

The contract therefore expects deterministic rejection and is intentionally RED
until the active #511 source owner tightens the nested sequence boundary.

## Stop line

This is persistence-integrity evidence only. It does not accept the revised
implementation plan and does not grant code, tool, execution, target, retest,
deployment, security-verdict, or attack-path authority. It performs no model
invocation and no target interaction.
