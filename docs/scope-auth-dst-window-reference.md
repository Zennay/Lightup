# Scope authorization: daylight-saving window reference

**Status:** proposed offline acceptance contract only; NOT production authorization evidence.

A grant validity interval must be evaluated using offset-aware absolute instants, with an inclusive beginning and **exclusive** expiry. The same local clock reading during daylight-saving fall-back can refer to two different instants. A scope grant that expires in the first occurrence must not revive during the second occurrence. The reverse direction must also be denied. Representation with different offsets for the same absolute instant must be equivalent.

## Acceptance matrix

- Repeated Europe/London 01:30 on 2026-10-25 has fold=0 and fold=1 one hour apart in UTC.
- A first-fold grant never licenses execution in the second fold, even when displayed wall-clock time appears earlier.
- A second-fold grant does not authorize a first-fold request.
- Expiration is exclusive down to microseconds; zero or inverted intervals deny.
- Naive, missing-offset and unexpected datetime object types fail closed.
- Valid timezone offsets are normalized before ordering, not compared by local clock text.

Run offline: `python -m unittest discover -s tests -p 'test_scope_auth_dst_window_reference.py' -v`.

## Integration boundary

Production owner **PR #107** must bind grant issuer, tenant, asset/capability, risk, approval/revocation and current trusted clock at admission, queue retry and dispatch. This isolated reference does none of that. It does not issue or verify grants, authorize a target, perform DNS/network I/O or execute capabilities. Ambiguous/nonexistent local wall times supplied by clients should be refused or explicitly resolved at intake; existing timezone-aware objects must never be mistaken for trusted issuer evidence. The system must fail closed when trusted time is unavailable. Before promotion require exact-head hosted CI, permanent VPS proof and the owning source review.
