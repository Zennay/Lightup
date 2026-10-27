# W27 — opt-in strict persisted finding evidence decoder (issues #856/#886)

Status: **DRAFT / HOLD / M3-M7 PLAN-LAB ONLY / NO MERGE / NO DEPLOY.**
Owner integration into the default `DomainStore` has **NOT** happened.

## Why this exists

`DomainStore._finding_from_row()` currently reconstructs evidence through
`tuple(json.loads(row["evidence_ids_json"]))`. A legacy JSON string can
turn into character IDs; an object turns into keys; deeply nested JSON can
raise `RecursionError`; invalid syntax can surface `JSONDecodeError`.
This is an **offline durable-input integrity concern**, not evidence of an
externally exploitable endpoint or a live incident.

Existing tests/docs-only owner contracts [#856](https://github.com/Zennay/Lightup/issues/856),
[#886](https://github.com/Zennay/Lightup/issues/886) and composition #885
stay the source of truth. This new pure reference is **independent** and
does not edit `src/lightup/domain.py` (owned by #828 and future #856
source successor), writes, schema, labsync, twin or target-capable code.

## Concrete optional reference

`src/lightup/finding_evidence_json_checked_optin_w27.py` exposes
`decode_finding_evidence_checked(raw)`. It accepts only built-in
UTF-8 JSON text and exact built-in JSON arrays, preserves the canonical
ordered string references including original textual whitespace, accepts
an empty array for manual findings, refuses blank/duplicate/non-string
members, and normalizes parse errors, scalar JSON, malformed types and
JSON recursion to **one generic evidence-integrity `ValueError`**.

Provisional *additional* bounds protect the pure reference from oversized
historic input: maximum 262,144 JSON bytes, 128 references, and 4,096 UTF-8
bytes per reference. These are **not yet the canonical compatibility
contract**. The original owner must inventory legitimate historic data
and choose validated limits before integration. The function cannot
authenticate, establish tenant provenance, verify evidence, or authorize
retest/remediation.

## Offline acceptance

`tests/test_finding_evidence_json_checked_optin_w27.py` contains 7
standard-library tests with a disposable real `DomainStore` SQLite row.
It injects synthetically corrupted historical evidence, feeds the raw
stored field to the opt-in decoder and proves denial leaves the SQLite
bytes unchanged. Positives cover ordered Unicode references and empty
manual arrays; negatives cover null/bool/object/string/number, broken
JSON, nonfinite numbers, mixed types, blanks, duplicate refs, bounded
nested JSON, oversized sources and Python polymorphism. The default
read path intentionally remains untouched.

Run on exact-head hosted preflight:

```sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_finding_evidence_json_checked_optin_w27.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_*.py'
```

A passing standalone opt-in test **does not satisfy** source owner
#856/#886 acceptance: the real `DomainStore.list_findings` selectors,
Security Twin, and retest updates still need strict production-boundary
checks and atomicity. Original owners, independent security/privacy
review, exact-head registered permanent VPS CI, latest-main composition
and release authority are mandatory. No client data, live target,
scanner, grant, active remediation or verified retest.
