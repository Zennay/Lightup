# WebSocket subprotocol metadata is not authority (offline reference)

The `Sec-WebSocket-Protocol` negotiation label is attacker-controlled transport metadata, not a verified authorization grant. A label such as `admin`, `scope=all` or a serialized token must never create, renew, revoke or transfer permission to run a capability.

The isolated, pure-stdlib test module `tests/test_scope_websocket_subprotocol_nonauthority_reference.py` checks fifteen fail-closed reference behaviors: a matching synthetic grant remains independent of the label, inactive/unverified grants cannot be revived, tenant/request/asset/capability mismatches and revision type confusion fail, missing or empty matching identities fail, forged string subclasses fail, and polymorphic envelopes fail. Truthy-but-nonboolean grant flags and identities absent on both sides also fail; the reference does not mutate input dictionaries. Hostile transport labels must not have attributes, length, equality, truthiness, iteration, or string conversion invoked. A hostile metadata object must not be inspected or coerced.

Run offline with `python -m unittest discover -s tests -p 'test_scope_websocket_subprotocol_nonauthority_reference.py' -v`.

**Trust limitation:** `issuer_verified` is a synthetic fixture boolean. These tests do not authenticate issuer provenance, enforce policy in the production executor, bind WebSocket handshakes to server-side run context, or authorize any actual target. No targets, DNS, sockets, scans, adapter activation or deployments are involved.

**Review/merge gate:** keep as draft until the exact commit is tested on Python 3.11 and 3.14 and the canonical permanent VPS CI lane, followed by scope-owner review. Do not treat CI on older commits as proof.
