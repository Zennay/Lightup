# W24 — expected-RED decoder-edge evidence integrity (issue #886)

**PLAN/LAB ONLY — tests/doc only — BRANCH-ONLY / HOLD / NO MERGE / NO DEPLOY.**

This is a standalone tests/docs child of the canonical #885 read-integrity
acceptance pack exact `7ea5fb7678967aa7f27916792d25a8c5897faa27`.
No source, schema, domain write, scanner, target, retest or installed entrypoint
is touched. Source owner #828 controls finding read queries; #856 controls
the future canonical evidence decoder. Do not collide with those owners.

## New bounded negative cases

The existing #886 decode contract checked broken JSON syntax, top-level
`null`, and integer. This additional adversarial batch requires the same
generic evidence-integrity `ValueError` for:

- a syntactically valid **deeply nested JSON array** likely to trip
  `json.loads` recursion handling (bounded to at most 2,048 levels);
- JSON `true`/`false` scalars, a JSON object, and a numeric exponent
  that can decode to a non-finite float.

For each rejected read, the original `evidence_ids_json` column must remain
byte-for-byte unchanged. A canonical two-reference `list[str]` baseline
must still survive with original order intact. These are synthetic malformed
**stored historical rows**, not attack instructions or proven external inputs.

## Expected result and ownership

The source parent currently reconstructs evidence with
`tuple(json.loads(row["evidence_ids_json"]))`. This can propagate decoder
exceptions or coerce non-array objects into iterable forms. The new tests
should remain **RED** until the source-owner decoder successor deliberately
converges each malformed shape to a deterministic evidence-integrity
`ValueError`. Do not mark RED as a green production gate or attempt to
silently normalize corrupted historical evidence.

Reproduction on a trusted disposable CI clone:

```sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_finding_evidence_decoder_adversarial_w24.py' -v
```

No trusted runner execution has been claimed by committing these files.
No standalone PR or extra canonical CI dispatch while the shared VPS lane
is queued. Owner integration, exact-head CI and independent security/privacy
review are required before promoting acceptance.
