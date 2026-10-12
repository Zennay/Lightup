# W30 — exact boundary evidence JSON tests (#856 / #886)

**Only synthetic M3/M7 PLAN/LAB, DRAFT/HOLD, NO MERGE / NO DEPLOY.** Based on immutable W27 opt-in [draft PR #1205](https://github.com/Zennay/Lightup/pull/1205) head `014952a9745f3936379327bd9ba3c09eaccaa1d6`; adds **tests and handoff only**. Does not alter decoder source, canonical `DomainStore._finding_from_row`, schema, any scope/authorization code, default CLI/web, main, or other worker-owned paths.

## Exact acceptance cases

Ten isolated offline unittest methods in `tests/test_finding_evidence_json_exact_boundaries_w30.py` exercise the existing W27 helper:

- Distinct 128-reference compact JSON of **exactly 262144 UTF-8 bytes** is readable and order preserving; one trailing byte must refuse before JSON parse.
- One exact **4096-byte** UTF-8 evidence reference passes; one two-byte codepoint beyond the budget fails.
- Exactly **128 different** refs pass, the 129th fails without duplicate ambiguity.
- JSON `\\u003a` and literal `:` decode to the same exact reference and must be rejected as a duplicate.
- Exact Unicode strings preserve their original spelling/order without NFKC conflation, trimming or modification. Visually similar references are distinct under the W27 **current** contract; original owner must decide whether this is appropriate for canonical IDs.
- Invalid surrogate escapes and nonstandard nested numeric constants collapse to one generic evidence-integrity `ValueError`.
- Empty historical evidence arrays and outer JSON whitespace remain allowed.
- Only exact built-in string is accepted as the input container; subclasses, bytes and objects refuse.

## Run on exact branch head

```sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_finding_evidence_json_exact_boundaries_w30.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_*.py'
```

The tests use no real tenant, target, client, network call, external action or persistent storage. They are pure decoder contract validation, **not proof that default finding reads use that decoder**. W27's size ceilings remain provisional and require original #828/#856 source owner historical compatibility review; no new security or client authorization is implied. Obtain exact-head registered self-hosted VPS CI and independent evidence/privacy review before any integration decision. Do not reinterpret hosted green as permanent VPS acceptance.
