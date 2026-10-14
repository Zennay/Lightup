# HTTP method capability authorization — offline reference (M7/ST5)

**Status:** proposed review contract, not production enforcement or proof of consent.

Host/CIDR membership is not permission to invoke every HTTP verb. The authorizing
issuer must bind **exact tenant + asset + explicit method/capability**, and the
executor must revalidate a current, non-revoked approval at every dispatch. A
read-only grant must never silently authorize state-changing verbs (POST, PUT,
PATCH, DELETE), HTTP tunnelling (CONNECT), diagnostics (TRACE), extension verbs,
or redirect-derived method changes.

This isolated reference intentionally rejects verbs outside GET, HEAD, POST, PUT,
PATCH and DELETE until a trusted production owner defines and authorizes an
additional capability. GET and HEAD are **not intrinsically safe**: real HTTP
handlers may mutate state. A future production gate must also bind the exact
approved operation, authentication context, risk ceiling, target identity,
redirect and retry policy, and enforce side-effect controls. Method membership
alone is insufficient.

## Ownership / safety
- This changes only an offline synthetic reference and documentation; PR #107
  retains production executor ownership. No production policy or adapter change.
- No real targets, DNS, sockets, scanners, dispatch, or activation.
- An offline passing test does **not** demonstrate runtime enforcement, issuer
  authenticity, durable revocation, consent, or race-free atomic admission.
- Do not merge as a claim of authorization safety. Require source-owner review,
  production-integrated denial cases, exact-head hosted and canonical permanent
  VPS runner evidence, and explicit release approval.

Offline test command:
`python -m unittest discover -s tests -p 'test_scope_http_method_capability_reference_20261008.py' -v`
