# LightUp #1161 — conservative offline HTTP/1.1 framing fixture gate

**Status:** Incubate M3/M7, PLAN/LAB ONLY, DRAFT/HOLD/NO MERGE/NO DEPLOY.  
**Boundary:** strictly add-only independent test-reference. No production parser, Nginx, Gunicorn, app, security or authorization source modification.

## Scope and ownership

Existing open issue [#1161](https://github.com/Zennay/Lightup/issues/1161) requires independent *installed* ingress proof for ambiguous Content-Length / Transfer-Encoding. Existing [DRAFT #1160](https://github.com/Zennay/Lightup/pull/1160) tests in-process WSGI and remains owned by its original worker. This separate reference has neither real Nginx/Gunicorn capture nor authority to modify the owner's files.

This PR adds two new paths:

- tests/scope_1161_http1_framing_fixture_gate.py — a pure, conservative, no-network lexical guard for explicitly invented HTTP/1.1 request bytes.
- tests/test_scope_1161_http1_framing_fixture_gate_20261012.py — synthetic matrix for duplicate identical/conflicting CL, mixed-case CL, CL/TE combos, hop-by-hop forwarding hints, invalid lengths, truncation, concatenated second requests, CRLF/obs-fold/control bytes, host and route constraints, exact bytes type, limits, and positive benign fixtures.

A valid result means **only** that a byte sequence fits this **artificial, deliberately restrictive** syntax subset. It does not establish what Nginx/Gunicorn accept on actual sockets. This is *not* a complete RFC-compliant HTTP parser, request-smuggling detection proof, production admission gate, or permission to contact any host. A parser could disagree at runtime despite this local gate.

## Conservative synthetic allowlist

Only request lines GET /health HTTP/1.1 and POST /clients HTTP/1.1, Host localhost, CRLF, at most 24 unique ASCII token-header fields, exact single-space header separator, no hop-by-hop transfer semantics, at most 8 KiB POST body and 16 KiB complete input. For POST, content-length must be one canonical nonnegative decimal integer exactly equal to the bytes present, and content-type exactly application/x-www-form-urlencoded. GET must have no body and no body-framing fields. Any ambiguity refuses the sample; deny-by-default is deliberate. The W2 hardening explicitly rejects Cookie/Authorization headers, forwarding/method/path-override hints, and raw form-body controls or non-ASCII bytes even where a real HTTP implementation might accept them. This is a **synthetic-fixture privacy and authority boundary**, not a claim about installed ingress.

This fixture helper never listens, connects, sends HTTP, checks permissions, issues grants or mutates tenant state. It contains no live client tokens and no real target names.

## Independent original-ingress owner proof (still required)

1. On a *disposable user-owned loopback-only* Nginx → Gunicorn fixture (not production), record installed binaries/versions, loaded config digest, backend deployment SHA and safe configuration provenance. The example template is insufficient.
2. Exercise in-scope clean GET/POST controls and malformed duplicate/content-length/transfer-encoding/truncated-body cases; capture sanitized edge and backend result, rejection point, exact request-correlation and backend request count. Never log Cookie, CSRF, authorization, secrets or PII.
3. Prove no second-request desync/routing and no session lookup, forged identity/CSRF, client mutation or authorization grant. Distinguish edge-generated 4xx from real backend 4xx.
4. Coordinate source ownership with #1160 WSGI, #1162 form, #1154/#1155 method, #1158 path, #1164 identity and #1170 cookies; fix actual ingress/source bugs in owning branches after review, not in this tests-only PR.
5. Require exact-head GitHub-hosted Python 3.11/3.14 preflight, separately registered permanent VPS CI, independent security/privacy/tenant review and explicit owner release approval. No merge/deploy or live target until these are satisfied.

## Reproduce on authorized CI

```shell
PYTHONPATH=src:tests python -m unittest -v test_scope_1161_http1_framing_fixture_gate_20261012
```

No synthetic-only success satisfies installed ingress acceptance. Keep #1161 OPEN.
