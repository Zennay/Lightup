# Issue #886 — corrupt legacy finding evidence decoder acceptance (RED)

This is a **tests/docs-only child** of `chatgpt/finding-read-evidence-integrity-red-20261007` at parent `1a6749098a85b00127cd711e3ab668215ee52ce8`. It adds no production source changes and deliberately does not supersede source owners #828 / #856.

## Gap

The current `DomainStore._finding_from_row` reconstructs persisted evidence with `tuple(json.loads(row["evidence_ids_json"]))`. The existing #856 tests cover structurally wrong yet syntactically valid JSON; this child tests the **decoder edge**: truncated JSON, invalid object text, JSON null, numeric scalar and boolean scalar. Today these can either leak `JSONDecodeError`/`TypeError` classes or be silently misinterpreted.

## Acceptance

- The future integrated decoder must raise **exact built-in `ValueError`** for any malformed JSON or top-level scalar, with stable evidence-integrity wording. Do not leak raw stored bytes or implementation exceptions.
- Every rejected read must leave the `evidence_ids_json` column bytes **identical**. No automatic rewrite or salvage.
- Ordered canonical arrays and the intentionally allowed empty manual array remain valid.
- Tenant/engagement filtering remains owned by #828. Write-side canonical evidence admissions remain owned by #851/#857. Lab integration remains owned by #184/#854.
- Only temporary SQLite and a synthetic operator/engagement/finding are used; no network, customer target, real proof collection, AI call, fix/retest execution, storage migration or deployment.

## Test semantics and handoff

`PYTHONPATH=src python -m unittest tests.test_finding_evidence_decoder_corrupt_json_red_20261010 -v`

Five negative tests are **deliberate `expectedFailure` RED acceptance canaries** until the production-read owner hardens the canonical decoder. A green unittest run with those expected failures **is not evidence of a fix**. The owner must absorb the exact edge cases into canonical source and convert these five `expectedFailure` markers to ordinary passing denials; any `unexpected success` requires review, not automatic closure.

This branch should remain **PR-less** while the older #828/#856 base is unmerged, to avoid duplicating pending self-hosted LightUp CI. The canonical LightUp repository has no registered self-hosted runner as of the October 10 VPS handoff; queued `LightUp CI` is not proof. Integrate only after independent read-owner review, source tests and valid CI on exact final SHA.

Scope remains M3/M7 evidence-remediation in **PLAN/LAB only**.
