# Offline anchored fictional scope-audit chain (issue #1556)

**LightUp status:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. This is an **opt-in, unwired** standard-library integrity helper, not a permission or deployment feature. It has no code path to grants, targets, network workers, SQLite, web login or handlers.

## Purpose and limits

A SHA-256-linked, strictly ordered fictional review timeline lets an operator compare a supplied synthetic JSON stream to a **previously and independently recorded trusted tip**. It detects missing, reordered, altered and replayed events *relative to that tip*. Any actor who can rewrite **both** the stream and the purported anchor can replace the entire chain undetected. SHA-256 is not a digital signature, origin verification, authenticated client consent, at-use revocation check or legal proof. The CLI cannot establish authenticity of the supplied anchor.

## Input

STDIN: one UTF-8 JSON object, `{"schema":"LIGHTUP-FICTIONAL-SCOPE-AUDIT-CHAIN-V1","events":[...]}`. The only top-level keys are `schema` and `events`. Event keys (all required, no extras):

- `seq`: exact integer 0, 1, ... N-1, no boolean or floats;
- `kind`: literal `REVIEW_OPENED` first, then `REVIEW_NOTE`, optionally terminal `REVIEW_WITHDRAWN`; these are **not** authorizations;
- `at`: canonical UTC `YYYY-MM-DDTHH:MM:SSZ`, strictly increasing;
- `scope_sha256`: lowercase 64-character hex fiction-only scope digest, fixed across the stream;
- `previous_sha256`: 64 zeroes for the first, prior event's `sha256` for subsequent records;
- `sha256`: lowercase SHA-256 over `b"LIGHTUP-FICTIONAL-SCOPE-AUDIT-CHAIN-V1\\x00"` followed by UTF-8/ASCII bytes of canonical JSON for the previous five fields; `json.dumps(body,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False)`.

All keys/types/values are validated before a review-only result is emitted. 32 KiB maximum input and 64 records maximum; duplicate JSON keys, nonfinite numbers, invalid UTF-8, unknown kinds, forged consent/approval fields, nonmonotonic time, scope digest change, withdrawn-stream continuations, incorrect/truncated/reordered chains or wrong anchor result in atomic **HOLD**. Inputs are never repeated into stdout.

## Run

```bash
PYTHONPATH=src python -m lightup.scope_audit_chain_offline \
  --synthetic-only --expected-tip <64-lowercase-hex-trusted-anchor> < fictional-chain.json

PYTHONPATH=src python -m unittest tests.test_scope_audit_chain_offline -v
```

Only `--synthetic-only` enables reviewing records. **Exit 3 + REVIEW_ONLY** means a fictional chain matches the supplied anchor; **exit 2 + HOLD** covers invalid/incomplete/ambiguous inputs. Both return `consent_verified:false`, `authorization_granted:false`, and `release_approved:false`. This module is not wired into normal CLI and does not confer any live authority.

## Append-only export continuity (independent old and new anchors)

The second **standalone, unwired** entry point checks that a newly received fictional audit export strictly extends a previously anchored one; it must neither mutate any historical record nor reopen a terminal withdrawal.

STDIN is one UTF-8 JSON object with exactly three keys:

```json
{"schema":"LIGHTUP-FICTIONAL-SCOPE-AUDIT-TRANSITION-V1","before":{"schema":"LIGHTUP-FICTIONAL-SCOPE-AUDIT-CHAIN-V1","events":[]},"after":{"schema":"LIGHTUP-FICTIONAL-SCOPE-AUDIT-CHAIN-V1","events":[]}}
```

The arrays above are *shape illustrations only*. Real fictional test input needs at least one fully hashed old event and at least one **additional** fully hashed new event. Each old/new packet independently satisfies the earlier complete-chain grammar, plus both caller-supplied 64-hex anchors. The entire original event sequence must remain an **identical prefix** of the proposed sequence; the new sequence must be strictly longer. A replayed/no-op candidate, truncated history, changed original field, rewritten chain with a newly calculated tip, schema downgrade, duplicate JSON keys, unknown authority field, addition after withdrawal, changed scope, altered clock ordering or unanchored old/new stream all produce atomic `HOLD`. Maximum aggregate stdin size is **69,632 bytes**, with original 32,768-byte / 64-event bounds applied independently to both packets.

```bash
PYTHONPATH=src python -m lightup.scope_audit_chain_transition_offline \
  --synthetic-only \
  --expected-old-tip <64-lowercase-hex-old-trusted-tip> \
  --expected-new-tip <64-lowercase-hex-new-trusted-tip> < fictional-transition.json

PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_audit_chain*offline.py' -v
```

The CLI emits only `REVIEW_ONLY` (exit code **3**, with counts of old/new/newly appended records) or `HOLD` (exit code **2**, all counts zero). `consent_verified`, `authorization_granted`, and `release_approved` are always `false`. Even two apparently valid anchors are **not** proof of source provenance if both were provided by the same untrusted actor. Importantly, this tool verifies offline *history continuity*, not live revocation, real human consent, digital signature, deployability, or a durable authorization record.

## Deterministic falsification coverage

Dedicated matrix `tests/test_scope_audit_chain_mutation_offline.py` exercises the actual 64-event capacity limit, 65-event HOLD, 64-position digest tampering, 64-position predecessor tampering, 192 exact integer-sequence type confusions, 64-position forged authorization flags, 64-position unknown event kinds, 20 independently rehashed prefix revisions, 15 truncation attempts, deeply nested JSON, invalid UTF-8 and duplicate fields. This is 483 targeted subcases across the primary matrices, besides ordinary standalone unit/real CLI tests. The tests run offline and never contact real targets.

## Ownership and integration

Seven entirely new owned paths only: `src/lightup/scope_audit_chain_offline.py`, `tests/test_scope_audit_chain_offline.py`, `src/lightup/scope_audit_chain_transition_offline.py`, `tests/test_scope_audit_chain_transition_offline.py`, `tests/test_scope_audit_chain_mutation_offline.py`, this document, and `.github/workflows/lightup-scope-audit-chain.yml`. The new hosted-only dual-Python isolated proof is supplementary; it does **not** replace the existing full preflight or named permanent VPS CI. Existing concurrent review (#1551), consent/scope digest (#1507/#1505), revocation (#554/#100) and CI/provenance (#1309) owners remain untouched. The operator has to independently authenticate a trustworthy anchor before relying on content integrity. No merge, release or real-world scope use is permitted without separate approved source-owner/security/privacy review, exact-release validation and human GO.
