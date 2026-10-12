# LightUp #1170 — Cookie ingress receipt shape (isolated offline reviewer)

Date: 2026-10-12. Owner scope: **add-only synthetic tests/docs, not Nginx, Gunicorn, security.py, app.py, production.py or #1169 source**. Base: immutable main `05b80319cd0581fed21fe9d8f565bcb0a56cd2df`.

## What this actually adds

- `tests/scope_1170_cookie_ingress_receipt_reference.py` is a deterministic, non-authorizing Python verifier for a synthetic structured receipt. It neither opens files nor makes network connections.
- `tests/test_scope_1170_cookie_ingress_receipt_reference_20261012.py` checks all 8 fixed cases, removal/duplication/spoofing, exact byte-shape control fixture, malformed metadata, downstream login/write/cookie-denial invariants, two-step request-reuse non-authority, and independently supplied *expected* commit/config/capture digests.
- The input has `fixture_only=True` **by construction**: even passing it does NOT imply that installed Nginx/Gunicorn was tested. The sample hashes are invented placeholders, not captured evidence.
- No production configuration, session parser, authentication path, request handler, default entrypoint, customer state or authorization decision changes.

## Why #1170 stays open

[Original issue #1170](https://github.com/Zennay/Lightup/issues/1170) identifies a **wire vs WSGI normalization gap**. [DRAFT #1169](https://github.com/Zennay/Lightup/pull/1169) handles an opt-in *WSGI-environ* cookie string. It cannot observe multiple raw Cookie headers after actual proxy/backend normalization. These tests are not an installed proxy acceptance or a substitute for #1169, and must not be represented as evidence of a remotely exploitable bug.

**Actual ingress/source owner must separately:**

1. Verify in an isolated, explicitly owned **loopback** Nginx→Gunicorn fixture how repeated raw Cookie headers, semicolon duplication, comma coalescing, quoting and control bytes are handled. No internet scan, no real user tokens, no production reload.
2. Record independently verifiable versions/loaded config digest, backend capture provenance, sanitized per-case results and edge vs backend rejection. Prove no privileged session lookup, writes, Set-Cookie or second-request confusion on denied cases.
3. Decide whether the synthetic reviewer's deliberately strict 'backend fields equal wire fields or reject at edge' model fits the installed topology; adjust owner tests after real evidence rather than claiming this oracle parses Nginx.
4. Obtain production source-owner + independent security/privacy review, clear tenant and revocation boundaries, exact latest-head GitHub-hosted acceptance **and distinct permanent self-hosted VPS CI**. An earlier green run is not exact-head proof.
5. Reconcile with active #1158 path-routing, #1161 request-framing, #1164 identity forwarding, #1167 canonical path, #1168 method and #1169 cookie guard owners before any safe latest-main composition.

## Execution

```bash
PYTHONPATH=tests python -m unittest -v test_scope_1170_cookie_ingress_receipt_reference_20261012
```

This command is documented for the authorized runner. Its presence is **not a claim that CI or VPS executed**. This isolated reference has no release authority and does not authenticate externally supplied captures or hash pins.

**Release status: Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD/NO MERGE/NO DEPLOY.** Keep #1170 OPEN until installed ingress proofs and explicit human approval. No target interaction/grants/scans/retests/deployment.
