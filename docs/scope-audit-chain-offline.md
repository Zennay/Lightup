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

## Ownership and integration

Four entirely new owned paths only: `src/lightup/scope_audit_chain_offline.py`, `tests/test_scope_audit_chain_offline.py`, this document, and `.github/workflows/lightup-scope-audit-chain.yml`. The new hosted-only dual-Python isolated proof is supplementary; it does **not** replace the existing full preflight or named permanent VPS CI. Existing concurrent review (#1551), consent/scope digest (#1507/#1505), revocation (#554/#100) and CI/provenance (#1309) owners remain untouched. The operator has to independently authenticate a trustworthy anchor before relying on content integrity. No merge, release or real-world scope use is permitted without separate approved source-owner/security/privacy review, exact-release validation and human GO.
