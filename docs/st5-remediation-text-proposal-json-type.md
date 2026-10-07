# ST5 remediation text-proposal JSON text exactness

Issue: #584  
Parent: #209 exact head `38c40d112751728c238dcf5d7ab556079528c38e`

## Purpose

The strict remediation text-proposal handoff accepts persisted raw JSON text.
Serialization produces an exact built-in `str`; direct Python callers can
instead supply subclasses with polymorphic behavior.

The persisted text boundary must remain exact before any truthiness check,
`.strip()`, duplicate-key-safe decoding, or proposal parsing.

## Required contract

- canonical producer JSON is an exact built-in `str` and remains valid;
- a `str` subclass carrying byte-for-byte canonical proposal JSON is rejected
  before text methods or JSON decoding;
- caller input is not coerced, normalized, or rewritten.

This slice owns only raw JSON input identity. It does not claim #209 source,
#452 live-validation atomicity, #467 producer atomicity, proposal content/model/
digest ownership, or the earlier #582/#583 boundaries.

## Why the current parent is expected RED

At #209 head `38c40d112751728c238dcf5d7ab556079528c38e`,
`future_remediation_text_proposal_from_json()` uses
`isinstance(raw, str)` and `raw.strip()`. A canonical-content `str`
subclass therefore reaches `json.loads()` and is accepted.

The source owner should absorb this proof with an exact built-in type check
before truthiness, string methods, or decode. Reject rather than normalize.

## Collision boundary

One regression module + this contract document only. No production/source or
existing test/doc changes; no scope-authorization or target-capable path.

## Safety

Persistence-integrity validation only. No external model call, network I/O,
target interaction, scan, tool execution, remediation, retest, deployment,
future-state resolution, verdict creation or attack-path mutation.
